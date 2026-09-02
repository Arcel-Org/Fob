use ratatui::{
    style::{Color, Modifier, Style},
    text::Span,
    widgets::Block,
    Frame,
};

use super::state::{AppState, Screen};

mod boot;
mod dashboard;
mod device_picker;
mod done;
mod error;
mod formatting;
mod unlock;
mod wizard;

// ── Palette ──────────────────────────────────────────────────────────────────
const BLUE: Color = Color::Rgb(79, 127, 255);
const WHITE: Color = Color::Rgb(220, 225, 235);
const MUTED: Color = Color::Rgb(130, 135, 150);
const DIM: Color = Color::Rgb(65, 68, 80);
const RED: Color = Color::Rgb(235, 80, 60);
const GOLD: Color = Color::Rgb(240, 180, 50);
const GREEN: Color = Color::Rgb(60, 200, 100);

fn accent() -> Style {
    Style::default().fg(BLUE)
}
fn muted() -> Style {
    Style::default().fg(MUTED)
}
fn dim() -> Style {
    Style::default().fg(DIM)
}
fn bold_white() -> Style {
    Style::default().fg(WHITE).add_modifier(Modifier::BOLD)
}
fn bold_blue() -> Style {
    Style::default().fg(BLUE).add_modifier(Modifier::BOLD)
}
fn bold_red() -> Style {
    Style::default().fg(RED).add_modifier(Modifier::BOLD)
}

// ── Entry point ───────────────────────────────────────────────────────────────
pub fn render(frame: &mut Frame, state: &AppState) {
    frame.render_widget(
        Block::default().style(Style::default().bg(Color::Rgb(13, 17, 23))),
        frame.area(),
    );

    match &state.screen {
        Screen::Boot => boot::render_boot(frame, state),
        Screen::DevicePicker => device_picker::render_device_picker(frame, state),
        Screen::Formatting => formatting::render_formatting(frame, state),
        Screen::SetupWizard(step) => wizard::render_wizard(frame, state, step.clone()),
        Screen::Unlock => unlock::render_unlock(frame, state),
        Screen::Dashboard => dashboard::render_dashboard(frame, state),
        Screen::Done => done::render_done(frame, state),
        Screen::Error(msg) => error::render_error(frame, msg),
    }
}

// ── Shared helpers ───────────────────────────────────────────────────────────
use ratatui::layout::Rect;

fn centered_rect(w: u16, h: u16, area: Rect) -> Rect {
    let x = area.x + area.width.saturating_sub(w) / 2;
    let y = area.y + area.height.saturating_sub(h) / 2;
    Rect::new(x, y, w.min(area.width), h.min(area.height))
}

fn hint_span(key: &str) -> Span<'_> {
    Span::styled(
        format!(" {} ", key),
        Style::default()
            .bg(Color::Rgb(30, 35, 45))
            .fg(BLUE)
            .add_modifier(Modifier::BOLD),
    )
}

fn sep_span(text: &str) -> Span<'_> {
    Span::styled(text, muted())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tui::state::{DashboardState, DashboardTab, Modal, PasswordForm, WizardStep};
    use fob_core::vault::{unlock_vault, VaultFile, VaultInitParams};
    use ratatui::{backend::TestBackend, Terminal};

    /// Render `state` into an in-memory buffer and flatten it to plain text,
    /// so tests can assert on what a user would actually see rendered —
    /// catching layout/wiring bugs that a pure state-mutation test can't
    /// (e.g. a hint that's computed but never reaches the screen).
    fn rendered_text(state: &AppState) -> String {
        let backend = TestBackend::new(100, 30);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal.draw(|f| render(f, state)).unwrap();
        let buffer = terminal.backend().buffer().clone();
        let mut out = String::new();
        for y in 0..buffer.area.height {
            for x in 0..buffer.area.width {
                out.push_str(buffer[(x, y)].symbol());
            }
            out.push('\n');
        }
        out
    }

    fn dashboard_state_with_modal(modal: Modal) -> AppState {
        dashboard_state(DashboardTab::Passwords, modal, false)
    }

    /// Build a `Screen::Dashboard` state on the given tab, optionally with
    /// one populated entry of the matching kind pushed into every tab's
    /// blob (so populated-state tests can flip tabs on the same fixture).
    fn dashboard_state(tab: DashboardTab, modal: Modal, populate: bool) -> AppState {
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
        let (slot, mut blob) = unlock_vault(&bytes, b"test-pass").unwrap();
        let vault_file = VaultFile::from_bytes(bytes).unwrap();

        if populate {
            blob.passwords.push(fob_core::types::PasswordEntry::new(
                "GitHub", "alice", "hunter2",
            ));
            blob.totps.push(fob_core::types::TotpEntry::new(
                "Example",
                "alice@example.com",
                b"12345678901234567890".to_vec(),
            ));
            blob.ssh_keys.push(
                fob_core::types::SshKeyEntry::new(
                    "laptop",
                    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEJm7X5tIxbUkIb6VLD91P65Cr0iqKyTKTDd0cYpQHtv test@example",
                    "-----BEGIN OPENSSH PRIVATE KEY-----\nfake\n-----END OPENSSH PRIVATE KEY-----",
                )
                .unwrap(),
            );
            blob.notes
                .push(fob_core::types::NoteEntry::new("Recovery", "1234-5678"));
        }

        let dash = DashboardState {
            vault_path: std::path::PathBuf::from("/tmp/does-not-matter/vault.fob"),
            vault_file,
            slot,
            passphrase: "test-pass".to_string(),
            blob,
            tab,
            selected: 0,
            modal,
            reveal: false,
            status: None,
            ssh_agent: None,
            clipboard: None,
        };

        let mut state = AppState::new(Vec::new());
        state.screen = Screen::Dashboard;
        state.dashboard = Some(dash);
        state
    }

    fn test_device(name: &str) -> fob_host::device::UsbDevice {
        fob_host::device::UsbDevice {
            name: name.to_string(),
            size_bytes: 32 * 1024 * 1024 * 1024,
            path: std::path::PathBuf::from("/mnt/test"),
            disk_node: "disk4".to_string(),
            serial: None,
            has_fob_vault: false,
        }
    }

    #[test]
    fn password_modal_shows_the_f2_generate_hint_when_password_field_is_active() {
        let form = PasswordForm {
            name: String::new(),
            username: String::new(),
            password: String::new(),
            field: 2, // Password field active
            cursor: 0,
            editing: None,
        };
        let state = dashboard_state_with_modal(Modal::AddPassword(form));
        let text = rendered_text(&state);
        assert!(
            text.contains("F2") && text.contains("generate"),
            "expected the F2 generate hint to render in the password modal:\n{text}"
        );
    }

    #[test]
    fn other_modals_do_not_show_the_f2_hint() {
        let form = crate::tui::state::NoteForm {
            title: String::new(),
            body: String::new(),
            field: 0,
            cursor: 0,
            editing: None,
        };
        let state = dashboard_state_with_modal(Modal::AddNote(form));
        let text = rendered_text(&state);
        assert!(
            !text.contains("F2"),
            "the note modal has no password field — it must not show the generate hint:\n{text}"
        );
    }

    // ── Setup wizard ────────────────────────────────────────────────────

    #[test]
    fn wizard_existing_vault_step_shows_open_update_and_fresh_options() {
        let mut state = AppState::new(vec![test_device("Kingston DataTraveler")]);
        state.screen = Screen::SetupWizard(WizardStep::ExistingVault);
        let text = rendered_text(&state);
        assert!(text.contains("Fob Detected"), "{text}");
        assert!(text.contains("Open") && text.contains("Update") && text.contains("Fresh setup"));
        assert!(text.contains("Kingston DataTraveler"), "{text}");
    }

    #[test]
    fn wizard_confirm_wipe_step_shows_warning_and_device_name() {
        let mut state = AppState::new(vec![test_device("SanDisk Ultra")]);
        state.screen = Screen::SetupWizard(WizardStep::ConfirmWipe);
        let text = rendered_text(&state);
        assert!(text.contains("WARNING"), "{text}");
        assert!(text.contains("SanDisk Ultra"), "{text}");
        assert!(text.contains("erase and continue"));
    }

    #[test]
    fn wizard_master_step_shows_masked_passphrase_dots() {
        let mut state = AppState::new(Vec::new());
        state.screen = Screen::SetupWizard(WizardStep::Master);
        state.wizard.main_pass = "hunter2hunter2".to_string();
        state.wizard.field = 0;
        state.wizard.cursor = state.wizard.main_pass.chars().count();
        let text = rendered_text(&state);
        assert!(
            text.contains("●●●●●●●●●●●●●●"),
            "expected 14 masked dots for the passphrase field:\n{text}"
        );
        assert!(
            !text.contains("hunter2"),
            "passphrase must never render in cleartext:\n{text}"
        );
    }

    #[test]
    fn wizard_master_step_mismatch_flash_shows_error_style() {
        let mut state = AppState::new(Vec::new());
        state.screen = Screen::SetupWizard(WizardStep::Master);
        state.wizard.main_pass = "correct-horse".to_string();
        state.wizard.main_pass_confirm = "incorrect-horse".to_string();
        state.wizard.mismatch_flash = 15;
        let text = rendered_text(&state);
        assert!(
            text.contains("match"),
            "expected the mismatch message to render when mismatch_flash is active:\n{text}"
        );
    }

    #[test]
    fn wizard_confirm_step_flags_a_short_passphrase_as_weak() {
        let mut state = AppState::new(vec![test_device("Drive")]);
        state.screen = Screen::SetupWizard(WizardStep::Confirm);
        state.wizard.main_pass = "short".to_string();
        let text = rendered_text(&state);
        assert!(text.contains("Short"), "{text}");
    }

    #[test]
    fn wizard_confirm_step_flags_a_long_passphrase_as_strong() {
        let mut state = AppState::new(vec![test_device("Drive")]);
        state.screen = Screen::SetupWizard(WizardStep::Confirm);
        state.wizard.main_pass = "a".repeat(20);
        let text = rendered_text(&state);
        assert!(text.contains("Strong"), "{text}");
    }

    // ── Unlock ──────────────────────────────────────────────────────────

    #[test]
    fn unlock_error_shown_state_renders_the_error_message() {
        let mut state = AppState::new(Vec::new());
        state.screen = Screen::Unlock;
        state.unlock.passphrase = "wrong-pass".to_string();
        state.unlock.cursor = state.unlock.passphrase.chars().count();
        state.unlock.error = Some("Incorrect passphrase".to_string());
        let text = rendered_text(&state);
        assert!(text.contains("Incorrect passphrase"), "{text}");
    }

    #[test]
    fn unlock_no_error_state_renders_no_error_text() {
        let mut state = AppState::new(Vec::new());
        state.screen = Screen::Unlock;
        let text = rendered_text(&state);
        assert!(!text.contains("Incorrect"));
    }

    // ── Dashboard tabs: empty and populated ──────────────────────────────

    #[test]
    fn every_dashboard_tab_shows_the_empty_hint_when_no_entries() {
        for tab in DashboardTab::ALL {
            let state = dashboard_state(tab, Modal::None, false);
            let text = rendered_text(&state);
            assert!(
                text.contains("Nothing here yet"),
                "tab {:?} should show the empty-state hint:\n{text}",
                tab
            );
        }
    }

    #[test]
    fn passwords_tab_populated_shows_entry_and_masked_password() {
        let state = dashboard_state(DashboardTab::Passwords, Modal::None, true);
        let text = rendered_text(&state);
        assert!(text.contains("GitHub"), "{text}");
        assert!(text.contains("alice"), "{text}");
        assert!(
            !text.contains("hunter2"),
            "password must be masked by default:\n{text}"
        );
    }

    #[test]
    fn totp_tab_populated_shows_issuer_and_account_but_hides_code_until_reveal() {
        let state = dashboard_state(DashboardTab::Totp, Modal::None, true);
        let text = rendered_text(&state);
        assert!(text.contains("Example"), "{text}");
        assert!(text.contains("alice@example.com"), "{text}");
        assert!(text.contains("press r to reveal"), "{text}");
    }

    #[test]
    fn ssh_tab_populated_shows_name_and_public_key_but_masks_private_key() {
        let state = dashboard_state(DashboardTab::Ssh, Modal::None, true);
        let text = rendered_text(&state);
        assert!(text.contains("laptop"), "{text}");
        assert!(text.contains("ssh-ed25519"), "{text}");
        assert!(
            !text.contains("BEGIN OPENSSH PRIVATE KEY"),
            "private key must be masked by default:\n{text}"
        );
    }

    #[test]
    fn notes_tab_populated_shows_title_but_masks_body() {
        let state = dashboard_state(DashboardTab::Notes, Modal::None, true);
        let text = rendered_text(&state);
        assert!(text.contains("Recovery"), "{text}");
        assert!(
            !text.contains("1234-5678"),
            "note body must be masked by default:\n{text}"
        );
    }

    // ── Delete confirmation ───────────────────────────────────────────────

    #[test]
    fn delete_confirmation_modal_shows_warning_and_keys() {
        let state = dashboard_state(DashboardTab::Passwords, Modal::ConfirmDelete, true);
        let text = rendered_text(&state);
        assert!(text.contains("Delete this entry"), "{text}");
        assert!(text.contains("delete") && text.contains("cancel"), "{text}");
    }

    // ── Edit-mode modals ──────────────────────────────────────────────────

    #[test]
    fn edit_mode_password_modal_shows_edit_title_not_add() {
        let form = PasswordForm {
            name: "GitHub".to_string(),
            username: "alice".to_string(),
            password: "hunter2".to_string(),
            field: 0,
            cursor: 0,
            editing: Some(0),
        };
        let state = dashboard_state_with_modal(Modal::AddPassword(form));
        let text = rendered_text(&state);
        assert!(text.contains("Edit Password"), "{text}");
        assert!(!text.contains("Add Password"), "{text}");
    }

    #[test]
    fn edit_mode_note_modal_shows_edit_title_not_add() {
        let form = crate::tui::state::NoteForm {
            title: "Recovery".to_string(),
            body: "1234-5678".to_string(),
            field: 0,
            cursor: 0,
            editing: Some(0),
        };
        let state = dashboard_state_with_modal(Modal::AddNote(form));
        let text = rendered_text(&state);
        assert!(text.contains("Edit Note"), "{text}");
        assert!(!text.contains("Add Note"), "{text}");
    }

    #[test]
    fn edit_mode_totp_modal_shows_edit_title_not_add() {
        let form = crate::tui::state::TotpForm {
            issuer: "Example".to_string(),
            account: "alice@example.com".to_string(),
            secret: "JBSWY3DPEHPK3PXP".to_string(),
            field: 0,
            cursor: 0,
            editing: Some(0),
        };
        let state = dashboard_state_with_modal(Modal::AddTotp(form));
        let text = rendered_text(&state);
        assert!(text.contains("Edit TOTP"), "{text}");
        assert!(!text.contains("Add TOTP"), "{text}");
    }

    #[test]
    fn edit_mode_ssh_modal_shows_edit_title_not_import() {
        let form = crate::tui::state::SshForm {
            name: "laptop".to_string(),
            public_key: "ssh-ed25519 AAAA...".to_string(),
            private_key: "-----BEGIN OPENSSH PRIVATE KEY-----".to_string(),
            field: 0,
            cursor: 0,
            editing: Some(0),
        };
        let state = dashboard_state_with_modal(Modal::AddSsh(form));
        let text = rendered_text(&state);
        assert!(text.contains("Edit SSH Key"), "{text}");
        assert!(!text.contains("Import SSH Key"), "{text}");
    }
}
