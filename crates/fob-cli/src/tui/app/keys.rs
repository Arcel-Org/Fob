use anyhow::Result;
use crossterm::event::{KeyCode, KeyModifiers};

use super::{handle_text_input, insert_str_at_cursor, App};
use crate::tui::state::{DashboardState, DashboardTab, Modal, Screen, UnlockState, WizardStep};

impl App {
    pub(super) fn handle_key(&mut self, key: KeyCode, mods: KeyModifiers) -> Result<bool> {
        if key == KeyCode::Char('c') && mods.contains(KeyModifiers::CONTROL) {
            return Ok(true);
        }

        let screen = self.state.screen.clone();
        match screen {
            Screen::Boot => {
                self.state.boot_tick = super::BOOT_TICKS;
            }
            Screen::Formatting => {
                // Block all input while the format thread is running.
            }
            Screen::DevicePicker => {
                self.handle_device_picker(key)?;
            }
            Screen::SetupWizard(step) => {
                if self.handle_wizard(key, step)? {
                    return Ok(true);
                }
            }
            Screen::Unlock => {
                self.handle_unlock(key);
            }
            Screen::Dashboard => {
                self.handle_dashboard(key)?;
            }
            Screen::Done => {
                return Ok(true);
            }
            Screen::Error(_) => {
                if matches!(key, KeyCode::Char('q') | KeyCode::Esc | KeyCode::Enter) {
                    return Ok(true);
                }
            }
        }

        Ok(false)
    }

    fn handle_device_picker(&mut self, key: KeyCode) -> Result<()> {
        let n = self.state.devices.len();
        match key {
            KeyCode::Char('q') | KeyCode::Esc => {
                // q exits from device picker
                self.state.screen = Screen::Error("Setup cancelled.".into());
            }
            KeyCode::Up | KeyCode::Char('k') => {
                if self.state.selected_device > 0 {
                    self.state.selected_device -= 1;
                }
            }
            KeyCode::Down | KeyCode::Char('j') => {
                if self.state.selected_device + 1 < n {
                    self.state.selected_device += 1;
                }
            }
            KeyCode::Enter | KeyCode::Char(' ') => {
                if let Some(dev) = self.state.devices.get(self.state.selected_device) {
                    let next = if dev.has_fob_vault {
                        WizardStep::ExistingVault
                    } else {
                        WizardStep::ConfirmWipe
                    };
                    self.state.screen = Screen::SetupWizard(next);
                    self.state.wizard.field = 0;
                    self.state.wizard.cursor = 0;
                }
            }
            // '1'..='9' only — quick-select maps to devices 1-9, and there's
            // no 10th-device meaning for '0' to map to. Excluding it here
            // (rather than matching is_ascii_digit(), which also accepts
            // '0') avoids an unsigned underflow computing `'0' - '1'`.
            KeyCode::Char(c @ '1'..='9') => {
                let idx = (c as usize) - ('1' as usize);
                if idx < n {
                    self.state.selected_device = idx;
                }
            }
            KeyCode::Char('r') | KeyCode::Char('R') => {
                self.state.devices = fob_host::device::enumerate_usb_devices();
                if self.state.selected_device >= self.state.devices.len() {
                    self.state.selected_device = self.state.devices.len().saturating_sub(1);
                }
            }
            _ => {}
        }
        Ok(())
    }

    fn handle_wizard(&mut self, key: KeyCode, step: WizardStep) -> Result<bool> {
        match step {
            WizardStep::ExistingVault => match key {
                KeyCode::Char('o') | KeyCode::Char('O') => {
                    self.state.unlock = UnlockState::default();
                    self.state.screen = Screen::Unlock;
                }
                KeyCode::Char('u') | KeyCode::Char('U') => {
                    self.state.update_mode = true;
                    match self.run_vault_update() {
                        Ok(()) => self.state.screen = Screen::Done,
                        Err(e) => self.state.screen = Screen::Error(e.to_string()),
                    }
                }
                KeyCode::Char('f') | KeyCode::Char('F') => {
                    self.state.update_mode = false;
                    self.state.screen = Screen::SetupWizard(WizardStep::ConfirmWipe);
                }
                KeyCode::Esc => {
                    self.state.screen = Screen::DevicePicker;
                }
                _ => {}
            },

            WizardStep::ConfirmWipe => match key {
                KeyCode::Char('y') | KeyCode::Char('Y') => {
                    if let Some(dev) = self.state.devices.get(self.state.selected_device).cloned() {
                        let (tx, rx) = std::sync::mpsc::channel();
                        std::thread::spawn(move || {
                            tx.send(fob_host::device::format_device(&dev)).ok();
                        });
                        self.state.format_rx = Some(rx);
                        self.state.screen = Screen::Formatting;
                    }
                }
                KeyCode::Char('n') | KeyCode::Char('N') | KeyCode::Esc => {
                    self.state.screen = Screen::DevicePicker;
                }
                _ => {}
            },

            WizardStep::Master => match key {
                KeyCode::Tab => {
                    self.state.wizard.field = (self.state.wizard.field + 1) % 2;
                    self.state.wizard.cursor = match self.state.wizard.field {
                        0 => self.state.wizard.main_pass.chars().count(),
                        _ => self.state.wizard.main_pass_confirm.chars().count(),
                    };
                }
                KeyCode::Enter => {
                    if self.state.wizard.field == 0 {
                        self.state.wizard.field = 1;
                        self.state.wizard.cursor =
                            self.state.wizard.main_pass_confirm.chars().count();
                    } else if !self.state.wizard.main_pass.is_empty()
                        && self.state.wizard.main_pass == self.state.wizard.main_pass_confirm
                    {
                        self.state.screen = Screen::SetupWizard(WizardStep::Confirm);
                        self.state.wizard.field = 0;
                        self.state.wizard.cursor = 0;
                    } else {
                        self.state.wizard.mismatch_flash = 15;
                    }
                }
                KeyCode::Esc => {
                    use zeroize::Zeroize;
                    self.state.wizard.main_pass.zeroize();
                    self.state.wizard.main_pass_confirm.zeroize();
                    self.state.screen = Screen::SetupWizard(WizardStep::ConfirmWipe);
                }
                _ => match self.state.wizard.field {
                    0 => handle_text_input(
                        &mut self.state.wizard.main_pass,
                        &mut self.state.wizard.cursor,
                        key,
                    ),
                    1 => handle_text_input(
                        &mut self.state.wizard.main_pass_confirm,
                        &mut self.state.wizard.cursor,
                        key,
                    ),
                    _ => {}
                },
            },

            WizardStep::Confirm => match key {
                KeyCode::Enter => match self.run_vault_init() {
                    Ok(()) => self.state.screen = Screen::Done,
                    Err(e) => self.state.screen = Screen::Error(e.to_string()),
                },
                KeyCode::Char('r') | KeyCode::Char('R') => {
                    self.state.wizard.recovery_enabled = !self.state.wizard.recovery_enabled;
                }
                KeyCode::Esc => {
                    self.state.screen = Screen::SetupWizard(WizardStep::Master);
                }
                _ => {}
            },
        }
        Ok(false)
    }

    /// Route a bracketed-paste event to whichever text field is currently
    /// active, inserting the whole pasted string at the cursor in one go.
    ///
    /// Without this, a multi-line paste (an SSH private key, a long note)
    /// would arrive as individual `KeyCode::Enter` presses per embedded
    /// newline — and Enter means "next field / save" in every form here, so
    /// the paste would silently truncate at the first line break instead of
    /// landing intact.
    pub(super) fn handle_paste(&mut self, text: &str) {
        let text = text.replace('\r', "");
        match &self.state.screen {
            Screen::SetupWizard(WizardStep::Master) => match self.state.wizard.field {
                0 => insert_str_at_cursor(
                    &mut self.state.wizard.main_pass,
                    &mut self.state.wizard.cursor,
                    &text,
                ),
                _ => insert_str_at_cursor(
                    &mut self.state.wizard.main_pass_confirm,
                    &mut self.state.wizard.cursor,
                    &text,
                ),
            },
            Screen::Unlock => insert_str_at_cursor(
                &mut self.state.unlock.passphrase,
                &mut self.state.unlock.cursor,
                &text,
            ),
            Screen::Dashboard => {
                if let Some(dash) = self.state.dashboard.as_mut() {
                    match &mut dash.modal {
                        Modal::AddPassword(form) => {
                            let field = match form.field {
                                0 => &mut form.name,
                                1 => &mut form.username,
                                _ => &mut form.password,
                            };
                            insert_str_at_cursor(field, &mut form.cursor, &text);
                        }
                        Modal::AddNote(form) => {
                            let field = match form.field {
                                0 => &mut form.title,
                                _ => &mut form.body,
                            };
                            insert_str_at_cursor(field, &mut form.cursor, &text);
                        }
                        Modal::AddTotp(form) => {
                            let field = match form.field {
                                0 => &mut form.issuer,
                                1 => &mut form.account,
                                _ => &mut form.secret,
                            };
                            insert_str_at_cursor(field, &mut form.cursor, &text);
                        }
                        Modal::AddSsh(form) => {
                            let field = match form.field {
                                0 => &mut form.name,
                                1 => &mut form.public_key,
                                _ => &mut form.private_key,
                            };
                            insert_str_at_cursor(field, &mut form.cursor, &text);
                        }
                        Modal::None | Modal::ConfirmDelete => {}
                    }
                }
            }
            _ => {}
        }
    }

    fn handle_unlock(&mut self, key: KeyCode) {
        match key {
            KeyCode::Enter => {
                if !self.state.unlock.passphrase.is_empty() {
                    self.try_unlock();
                }
            }
            KeyCode::Esc => {
                self.state.unlock = UnlockState::default();
                self.state.screen = Screen::SetupWizard(WizardStep::ExistingVault);
            }
            _ => handle_text_input(
                &mut self.state.unlock.passphrase,
                &mut self.state.unlock.cursor,
                key,
            ),
        }
    }

    /// Attempt to unlock the vault on the selected device with the entered
    /// passphrase. Wrong passphrase and duress passphrase are deliberately
    /// indistinguishable here — both just show "Incorrect passphrase."
    fn try_unlock(&mut self) {
        use zeroize::Zeroize;

        let dev = match self.state.devices.get(self.state.selected_device) {
            Some(d) => d.clone(),
            None => {
                self.state.unlock.error = Some("No device selected.".into());
                return;
            }
        };
        let vault_path = dev.path.join("vault.fob");

        if let Ok(meta) = std::fs::metadata(&vault_path) {
            if meta.len() > fob_core::format::MAX_VAULT_SIZE as u64 {
                self.state.unlock.error = Some(format!(
                    "vault.fob is {} bytes, exceeding the maximum of {} bytes",
                    meta.len(),
                    fob_core::format::MAX_VAULT_SIZE
                ));
                return;
            }
        }

        let bytes = match std::fs::read(&vault_path) {
            Ok(b) => b,
            Err(e) => {
                self.state.unlock.error = Some(format!("Could not read vault: {e}"));
                return;
            }
        };

        let mut passphrase = self.state.unlock.passphrase.clone();
        match fob_core::vault::unlock_vault_with_duress_wipe(
            &bytes,
            passphrase.as_bytes(),
            &vault_path,
        ) {
            Ok((slot, blob)) => {
                let vault_file = match fob_core::vault::VaultFile::from_bytes(bytes) {
                    Ok(vf) => vf,
                    Err(e) => {
                        self.state.unlock.error = Some(e.to_string());
                        return;
                    }
                };
                self.state.dashboard = Some(DashboardState {
                    vault_path,
                    vault_file,
                    slot,
                    passphrase,
                    blob,
                    tab: DashboardTab::Passwords,
                    selected: 0,
                    modal: Modal::None,
                    reveal: false,
                    status: None,
                    ssh_agent: None,
                    clipboard: None,
                });
                self.state.dashboard.as_mut().unwrap().sync_ssh_agent();
                self.state.unlock = UnlockState::default();
                self.state.screen = Screen::Dashboard;
            }
            Err(_) => {
                // `passphrase` (the clone made above for this attempt) never
                // moved anywhere on this path — zeroize it too, not just the
                // original field, or the just-typed passphrase is left
                // sitting in a second, unwiped heap allocation every time
                // someone mistypes it (a routine, frequent event).
                passphrase.zeroize();
                self.state.unlock.passphrase.zeroize();
                self.state.unlock.passphrase.clear();
                self.state.unlock.error = Some("Incorrect passphrase.".into());
            }
        }
    }
}
