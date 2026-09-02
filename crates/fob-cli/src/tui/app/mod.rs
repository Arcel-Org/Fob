use std::path::PathBuf;
use std::time::{Duration, Instant};

use anyhow::Result;
use crossterm::event::{self, Event, KeyCode};
use ratatui::{backend::CrosstermBackend, Terminal};

use super::{
    screens,
    state::{AppState, Screen, WizardStep},
};
use fob_host::device;

mod dashboard_keys;
mod keys;
mod terminal;
mod vault_ops;

pub use terminal::run;

const TICK_RATE: Duration = Duration::from_millis(60);
const BOOT_TICKS: u8 = 12;

pub struct App {
    pub state: AppState,
}

impl App {
    pub fn new(device: Option<PathBuf>) -> Self {
        let devices = device::enumerate_usb_devices();
        let mut state = AppState::new(devices);

        if let Some(dev_path) = device {
            for (i, d) in state.devices.iter().enumerate() {
                if d.path == dev_path {
                    state.selected_device = i;
                    break;
                }
            }
        }

        Self { state }
    }

    fn run_loop(
        &mut self,
        terminal: &mut Terminal<CrosstermBackend<std::io::Stdout>>,
    ) -> Result<()> {
        let mut last_tick = Instant::now();

        loop {
            terminal.draw(|frame| screens::render(frame, &self.state))?;

            let timeout = TICK_RATE
                .checked_sub(last_tick.elapsed())
                .unwrap_or(Duration::ZERO);

            if event::poll(timeout)? {
                match event::read()? {
                    Event::Key(key) => {
                        if self.handle_key(key.code, key.modifiers)? {
                            return Ok(());
                        }
                    }
                    Event::Paste(text) => self.handle_paste(&text),
                    _ => {}
                }
            }

            if last_tick.elapsed() >= TICK_RATE {
                self.tick();
                last_tick = Instant::now();
            }
        }
    }

    fn tick(&mut self) {
        self.state.tick = self.state.tick.wrapping_add(1);

        if self.state.screen == Screen::Boot {
            self.state.boot_tick = self.state.boot_tick.saturating_add(1);
            if self.state.boot_tick >= BOOT_TICKS {
                // Always land on the picker, even with zero drives — it has
                // its own empty state with a rescan key, so plugging in a
                // drive after launch doesn't require restarting the app.
                self.state.screen = Screen::DevicePicker;
            }
        }

        if self.state.wizard.mismatch_flash > 0 {
            self.state.wizard.mismatch_flash -= 1;
        }

        // Poll background format thread.
        if self.state.screen == Screen::Formatting {
            if let Some(rx) = &self.state.format_rx {
                if let Ok(result) = rx.try_recv() {
                    self.state.format_rx = None;
                    match result {
                        Ok(()) => {
                            self.state.devices = fob_host::device::enumerate_usb_devices();
                            if let Some(idx) =
                                self.state.devices.iter().position(|d| d.name == "FOB")
                            {
                                self.state.selected_device = idx;
                            }
                            self.state.screen = Screen::SetupWizard(WizardStep::Master);
                            self.state.wizard.field = 0;
                            self.state.wizard.cursor = 0;
                        }
                        Err(e) => {
                            self.state.screen = Screen::Error(e.to_string());
                        }
                    }
                }
            }
        }

        // Auto-clear the clipboard 30s after a copy.
        if let Some(dash) = self.state.dashboard.as_mut() {
            if let Some((text, clear_at)) = &dash.clipboard {
                if std::time::Instant::now() >= *clear_at {
                    let _ = fob_host::clipboard::clear_if_unchanged(text);
                    dash.clipboard = None;
                }
            }
        }
    }
}

/// Byte offset of the `char_idx`-th character in `s` (or `s.len()` if
/// `char_idx` is at or past the end) — every mutation below needs this since
/// `String::insert`/`remove` take byte offsets but the cursor tracks chars.
fn char_to_byte_idx(s: &str, char_idx: usize) -> usize {
    s.char_indices()
        .nth(char_idx)
        .map(|(b, _)| b)
        .unwrap_or(s.len())
}

/// Insert a whole pasted string at the cursor in one go (as opposed to
/// `handle_text_input`, which handles one key at a time).
fn insert_str_at_cursor(field: &mut String, cursor: &mut usize, text: &str) {
    let byte_idx = char_to_byte_idx(field, *cursor);
    field.insert_str(byte_idx, text);
    *cursor += text.chars().count();
}

fn handle_text_input(field: &mut String, cursor: &mut usize, key: KeyCode) {
    match key {
        KeyCode::Char(c) => {
            let byte_idx = char_to_byte_idx(field, *cursor);
            field.insert(byte_idx, c);
            *cursor += 1;
        }
        KeyCode::Backspace => {
            if *cursor > 0 {
                *cursor -= 1;
                let byte_idx = char_to_byte_idx(field, *cursor);
                field.remove(byte_idx);
            }
        }
        KeyCode::Delete => {
            if *cursor < field.chars().count() {
                let byte_idx = char_to_byte_idx(field, *cursor);
                field.remove(byte_idx);
            }
        }
        KeyCode::Left => *cursor = cursor.saturating_sub(1),
        KeyCode::Right => *cursor = (*cursor + 1).min(field.chars().count()),
        KeyCode::Home => *cursor = 0,
        KeyCode::End => *cursor = field.chars().count(),
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tui::state::{DashboardState, DashboardTab, Modal, SshForm};
    use crossterm::event::KeyModifiers;
    use fob_core::types::PasswordEntry;
    use fob_core::vault::{unlock_vault, VaultFile, VaultInitParams};

    fn app_with_dashboard() -> (App, std::path::PathBuf, tempfile_dir::TempDir) {
        let dir = tempfile_dir::TempDir::new();
        let vault_path = dir.path().join("vault.fob");

        let bytes = fob_core::vault::init_vault(VaultInitParams {
            main_passphrase: b"test-pass".to_vec(),
            decoy_passphrase: None,
            duress_passphrase: None,
            vault_size: 256 * 1024,
            decoy_blob: None,
            kdf_params: fob_core::vault::KdfParams::pbkdf2(1000),
            recovery_pubkey: None,
        })
        .unwrap();
        std::fs::write(&vault_path, &bytes).unwrap();

        let (slot, mut blob) = unlock_vault(&bytes, b"test-pass").unwrap();
        blob.passwords
            .push(PasswordEntry::new("GitHub", "alice", "hunter1"));
        let vault_file = VaultFile::from_bytes(bytes).unwrap();

        let dash = DashboardState {
            vault_path: vault_path.clone(),
            vault_file,
            slot,
            passphrase: "test-pass".to_string(),
            blob,
            tab: DashboardTab::Passwords,
            selected: 0,
            modal: Modal::None,
            reveal: false,
            status: None,
            ssh_agent: None,
            clipboard: None,
        };
        // Persist the entry so the dashboard's on-disk state matches its in-memory state.
        let mut dash = dash;
        dash.save().unwrap();

        let mut state = AppState::new(Vec::new());
        state.screen = Screen::Dashboard;
        state.dashboard = Some(dash);

        (App { state }, vault_path, dir)
    }

    fn press(app: &mut App, key: KeyCode) {
        app.handle_key(key, KeyModifiers::NONE).unwrap();
    }

    #[test]
    fn edit_updates_existing_entry_without_duplicating_it() {
        let (mut app, vault_path, _dir) = app_with_dashboard();
        let original_id = app.state.dashboard.as_ref().unwrap().blob.passwords[0].id;

        press(&mut app, KeyCode::Char('e')); // open edit modal, prefilled
        press(&mut app, KeyCode::Tab); // name -> username
        press(&mut app, KeyCode::Tab); // username -> password field
        for _ in 0.."hunter1".len() {
            press(&mut app, KeyCode::Backspace);
        }
        for c in "hunter2".chars() {
            press(&mut app, KeyCode::Char(c));
        }
        press(&mut app, KeyCode::Enter); // submit

        let dash = app.state.dashboard.as_ref().unwrap();
        assert!(matches!(dash.modal, Modal::None));
        assert_eq!(
            dash.blob.passwords.len(),
            1,
            "edit must not create a duplicate entry"
        );
        assert_eq!(
            dash.blob.passwords[0].id, original_id,
            "editing must preserve the entry's id"
        );
        assert_eq!(
            dash.blob.passwords[0].name, "GitHub",
            "untouched field must be preserved"
        );
        assert_eq!(dash.blob.passwords[0].password.expose(), "hunter2");

        // And the edit actually reached disk, not just in-memory state.
        let reloaded_bytes = std::fs::read(&vault_path).unwrap();
        let (_, reloaded) = unlock_vault(&reloaded_bytes, b"test-pass").unwrap();
        assert_eq!(reloaded.passwords.len(), 1);
        assert_eq!(reloaded.passwords[0].password.expose(), "hunter2");
    }

    #[test]
    fn escape_cancels_edit_without_changing_the_entry() {
        let (mut app, _vault_path, _dir) = app_with_dashboard();

        press(&mut app, KeyCode::Char('e'));
        for c in "should-not-be-saved".chars() {
            press(&mut app, KeyCode::Char(c));
        }
        press(&mut app, KeyCode::Esc);

        let dash = app.state.dashboard.as_ref().unwrap();
        assert!(matches!(dash.modal, Modal::None));
        assert_eq!(dash.blob.passwords[0].name, "GitHub");
    }

    #[test]
    fn delete_keeps_selection_on_the_entry_that_slid_into_this_row() {
        // Regression test: deleting index 1 out of [A,B,C,D] must land the
        // selection on C (which slides into row 1), not unconditionally
        // jump back to row 0 (A) regardless of which index was removed.
        let (mut app, _vault_path, _dir) = app_with_dashboard();
        let dash = app.state.dashboard.as_mut().unwrap();
        dash.blob.passwords.clear();
        for name in ["A", "B", "C", "D"] {
            dash.blob
                .passwords
                .push(PasswordEntry::new(name, "user", "pw"));
        }
        dash.selected = 1; // "B"

        press(&mut app, KeyCode::Char('d'));
        press(&mut app, KeyCode::Char('y'));

        let dash = app.state.dashboard.as_ref().unwrap();
        assert_eq!(dash.blob.passwords.len(), 3);
        assert_eq!(
            dash.blob.passwords[dash.selected].name, "C",
            "selection should follow the entry that slid into the deleted row"
        );
    }

    #[test]
    fn deleting_the_last_entry_clamps_selection_to_the_new_last_entry() {
        let (mut app, _vault_path, _dir) = app_with_dashboard();
        let dash = app.state.dashboard.as_mut().unwrap();
        dash.blob.passwords.clear();
        for name in ["A", "B", "C"] {
            dash.blob
                .passwords
                .push(PasswordEntry::new(name, "user", "pw"));
        }
        dash.selected = 2; // "C", the last entry

        press(&mut app, KeyCode::Char('d'));
        press(&mut app, KeyCode::Char('y'));

        let dash = app.state.dashboard.as_ref().unwrap();
        assert_eq!(dash.blob.passwords.len(), 2);
        assert_eq!(dash.selected, 1);
        assert_eq!(dash.blob.passwords[dash.selected].name, "B");
    }

    #[test]
    fn zero_digit_in_device_picker_does_not_panic() {
        // Regression test: '0' is_ascii_digit() but the quick-select maps
        // '1'..='9' to indices 0..=8 — computing ('0' as usize) - ('1' as
        // usize) used to underflow-panic in debug builds.
        let mut state = AppState::new(Vec::new());
        state.screen = Screen::DevicePicker;
        let mut app = App { state };
        press(&mut app, KeyCode::Char('0'));
        assert_eq!(app.state.selected_device, 0);
    }

    #[test]
    fn text_input_inserts_at_cursor_not_just_at_end() {
        let mut field = "helloworld".to_string();
        let mut cursor = 5; // between "hello" and "world"
        handle_text_input(&mut field, &mut cursor, KeyCode::Char(' '));
        assert_eq!(field, "hello world");
        assert_eq!(cursor, 6);
    }

    #[test]
    fn text_input_backspace_removes_char_before_cursor() {
        let mut field = "hello world".to_string();
        let mut cursor = 6; // right after the space
        handle_text_input(&mut field, &mut cursor, KeyCode::Backspace);
        assert_eq!(field, "helloworld");
        assert_eq!(cursor, 5);
    }

    #[test]
    fn text_input_backspace_at_start_is_a_no_op() {
        let mut field = "hello".to_string();
        let mut cursor = 0;
        handle_text_input(&mut field, &mut cursor, KeyCode::Backspace);
        assert_eq!(field, "hello");
        assert_eq!(cursor, 0);
    }

    #[test]
    fn text_input_delete_removes_char_at_cursor() {
        let mut field = "hello".to_string();
        let mut cursor = 0;
        handle_text_input(&mut field, &mut cursor, KeyCode::Delete);
        assert_eq!(field, "ello");
        assert_eq!(cursor, 0);
    }

    #[test]
    fn text_input_delete_at_end_is_a_no_op() {
        let mut field = "hello".to_string();
        let mut cursor = 5;
        handle_text_input(&mut field, &mut cursor, KeyCode::Delete);
        assert_eq!(field, "hello");
        assert_eq!(cursor, 5);
    }

    #[test]
    fn text_input_left_right_home_end_move_cursor_within_bounds() {
        let mut field = "abc".to_string();
        let mut cursor = 1;
        handle_text_input(&mut field, &mut cursor, KeyCode::Left);
        assert_eq!(cursor, 0);
        handle_text_input(&mut field, &mut cursor, KeyCode::Left);
        assert_eq!(cursor, 0, "cursor must not go below 0");

        handle_text_input(&mut field, &mut cursor, KeyCode::End);
        assert_eq!(cursor, 3);
        handle_text_input(&mut field, &mut cursor, KeyCode::Right);
        assert_eq!(cursor, 3, "cursor must not exceed the field length");

        handle_text_input(&mut field, &mut cursor, KeyCode::Home);
        assert_eq!(cursor, 0);
    }

    #[test]
    fn text_input_is_unicode_safe() {
        // "café" — 'é' is 2 bytes in UTF-8, so a naive byte-offset cursor
        // would panic (or silently corrupt the string) inserting/removing
        // right after it. The cursor tracks *chars*, not bytes.
        let mut field = "café".to_string();
        let mut cursor = 4; // after the 'é', i.e. at the end
        assert_eq!(cursor, field.chars().count());

        handle_text_input(&mut field, &mut cursor, KeyCode::Char('!'));
        assert_eq!(field, "café!");

        handle_text_input(&mut field, &mut cursor, KeyCode::Backspace);
        handle_text_input(&mut field, &mut cursor, KeyCode::Backspace);
        assert_eq!(field, "caf");
    }

    #[test]
    fn f2_generates_a_password_only_when_the_password_field_is_active() {
        let (mut app, _vault_path, _dir) = app_with_dashboard();
        press(&mut app, KeyCode::Char('a')); // open Add Password
        press(&mut app, KeyCode::F(2)); // field 0 (Name) is active — must be a no-op
        {
            let dash = app.state.dashboard.as_ref().unwrap();
            let Modal::AddPassword(form) = &dash.modal else {
                panic!("expected AddPassword modal");
            };
            assert_eq!(form.name, "", "F2 must not touch the Name field");
        }

        press(&mut app, KeyCode::Tab); // -> Username
        press(&mut app, KeyCode::Tab); // -> Password
        press(&mut app, KeyCode::F(2));

        let dash = app.state.dashboard.as_ref().unwrap();
        let Modal::AddPassword(form) = &dash.modal else {
            panic!("expected AddPassword modal");
        };
        assert_eq!(form.password.chars().count(), 20);
        assert_eq!(form.cursor, 20);
    }

    #[test]
    fn insert_str_at_cursor_splices_in_the_whole_string_at_once() {
        let mut field = "ab".to_string();
        let mut cursor = 1; // between 'a' and 'b'
        insert_str_at_cursor(&mut field, &mut cursor, "XYZ");
        assert_eq!(field, "aXYZb");
        assert_eq!(cursor, 4);
    }

    #[test]
    fn paste_into_multiline_field_preserves_every_line_without_truncating() {
        // Regression test: before bracketed paste was enabled, a multi-line
        // paste (e.g. a real SSH private key) arrived as individual key
        // events, and each embedded newline fired as a plain `Enter`
        // keypress — which every form here treats as "advance field / save",
        // silently truncating the paste at the first line break.
        let (mut app, _vault_path, _dir) = app_with_dashboard();
        let dash = app.state.dashboard.as_mut().unwrap();
        dash.modal = Modal::AddSsh(SshForm {
            name: String::new(),
            public_key: String::new(),
            private_key: String::new(),
            field: 2, // private_key
            cursor: 0,
            editing: None,
        });

        let pem =
            "-----BEGIN OPENSSH PRIVATE KEY-----\nline2\nline3\n-----END OPENSSH PRIVATE KEY-----";
        app.handle_paste(pem);

        let dash = app.state.dashboard.as_ref().unwrap();
        let Modal::AddSsh(form) = &dash.modal else {
            panic!("modal changed unexpectedly — paste must not trigger save/advance");
        };
        assert_eq!(form.private_key, pem);
        assert_eq!(form.cursor, pem.chars().count());
    }

    mod tempfile_dir {
        //! Minimal disposable-directory helper — avoids adding a `tempfile`
        //! dependency just for two tests.
        pub struct TempDir(std::path::PathBuf);

        impl TempDir {
            pub fn new() -> Self {
                let path = std::env::temp_dir().join(format!(
                    "fob-app-test-{}-{}",
                    std::process::id(),
                    std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap()
                        .as_nanos()
                ));
                std::fs::create_dir_all(&path).unwrap();
                Self(path)
            }

            pub fn path(&self) -> &std::path::Path {
                &self.0
            }
        }

        impl Drop for TempDir {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }
    }
}
