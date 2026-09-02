use anyhow::Result;
use crossterm::event::KeyCode;

use super::{handle_text_input, App};
use crate::tui::state::{
    DashboardTab, Modal, NoteForm, PasswordForm, Screen, SshForm, TotpForm, WizardStep,
};

impl App {
    pub(super) fn handle_dashboard(&mut self, key: KeyCode) -> Result<()> {
        let Some(dash) = self.state.dashboard.as_ref() else {
            return Ok(());
        };

        if !matches!(dash.modal, Modal::None) {
            self.handle_dashboard_modal(key);
            return Ok(());
        }

        let dash = self.state.dashboard.as_mut().unwrap();
        match key {
            KeyCode::Char('q') | KeyCode::Esc => {
                self.state.dashboard = None;
                self.state.screen = Screen::SetupWizard(WizardStep::ExistingVault);
            }
            KeyCode::Tab => {
                let idx = (dash.tab.index() + 1) % DashboardTab::ALL.len();
                dash.tab = DashboardTab::ALL[idx];
                dash.selected = 0;
                dash.reveal = false;
            }
            KeyCode::BackTab => {
                let n = DashboardTab::ALL.len();
                let idx = (dash.tab.index() + n - 1) % n;
                dash.tab = DashboardTab::ALL[idx];
                dash.selected = 0;
                dash.reveal = false;
            }
            KeyCode::Char(c @ '1'..='4') => {
                let idx = (c as usize) - ('1' as usize);
                dash.tab = DashboardTab::ALL[idx];
                dash.selected = 0;
                dash.reveal = false;
            }
            KeyCode::Up | KeyCode::Char('k') => {
                if dash.selected > 0 {
                    dash.selected -= 1;
                    dash.reveal = false;
                }
            }
            KeyCode::Down | KeyCode::Char('j') => {
                if dash.selected + 1 < dash.tab_len() {
                    dash.selected += 1;
                    dash.reveal = false;
                }
            }
            KeyCode::Char('a') => {
                dash.modal = match dash.tab {
                    DashboardTab::Passwords => Modal::AddPassword(PasswordForm::default()),
                    DashboardTab::Totp => Modal::AddTotp(TotpForm::default()),
                    DashboardTab::Ssh => Modal::AddSsh(SshForm::default()),
                    DashboardTab::Notes => Modal::AddNote(NoteForm::default()),
                };
                dash.status = None;
            }
            KeyCode::Char('d') => {
                if dash.tab_len() > 0 {
                    dash.modal = Modal::ConfirmDelete;
                }
            }
            KeyCode::Char('e') => {
                let idx = dash.selected;
                dash.modal = match dash.tab {
                    DashboardTab::Passwords => dash
                        .blob
                        .passwords
                        .get(idx)
                        .map(|e| Modal::AddPassword(PasswordForm::for_edit(idx, e))),
                    DashboardTab::Totp => dash
                        .blob
                        .totps
                        .get(idx)
                        .map(|e| Modal::AddTotp(TotpForm::for_edit(idx, e))),
                    DashboardTab::Ssh => dash
                        .blob
                        .ssh_keys
                        .get(idx)
                        .map(|e| Modal::AddSsh(SshForm::for_edit(idx, e))),
                    DashboardTab::Notes => dash
                        .blob
                        .notes
                        .get(idx)
                        .map(|e| Modal::AddNote(NoteForm::for_edit(idx, e))),
                }
                .unwrap_or(Modal::None);
                dash.status = None;
            }
            KeyCode::Char('r') | KeyCode::Enter => {
                dash.reveal = !dash.reveal;
            }
            KeyCode::Char('c') => {
                if let Some(text) = dash.copyable_text() {
                    match fob_host::clipboard::copy(&text) {
                        Ok(()) => {
                            dash.clipboard = Some((
                                text,
                                std::time::Instant::now() + fob_host::clipboard::CLEAR_AFTER,
                            ));
                            dash.status = Some("Copied — clipboard clears in 30s.".into());
                        }
                        Err(e) => dash.status = Some(format!("Copy failed: {e}")),
                    }
                }
            }
            _ => {}
        }
        Ok(())
    }

    fn handle_dashboard_modal(&mut self, key: KeyCode) {
        let Some(dash) = self.state.dashboard.as_mut() else {
            return;
        };

        if key == KeyCode::Esc {
            dash.modal = Modal::None;
            return;
        }

        match &mut dash.modal {
            Modal::None => {}

            Modal::ConfirmDelete => {
                if matches!(key, KeyCode::Char('y') | KeyCode::Char('Y')) {
                    let idx = dash.selected;
                    match dash.tab {
                        DashboardTab::Passwords if idx < dash.blob.passwords.len() => {
                            dash.blob.passwords.remove(idx);
                        }
                        DashboardTab::Totp if idx < dash.blob.totps.len() => {
                            dash.blob.totps.remove(idx);
                        }
                        DashboardTab::Ssh if idx < dash.blob.ssh_keys.len() => {
                            dash.blob.ssh_keys.remove(idx);
                        }
                        DashboardTab::Notes if idx < dash.blob.notes.len() => {
                            dash.blob.notes.remove(idx);
                        }
                        _ => {}
                    }
                    // Keep the highlight on the entry that slid into this
                    // row, rather than always jumping back one row
                    // regardless of which index was actually removed —
                    // only clamp when the deleted row was the last one.
                    let new_len = dash.tab_len();
                    if dash.selected >= new_len {
                        dash.selected = new_len.saturating_sub(1);
                    }
                    dash.modal = Modal::None;
                    dash.status = Some(match dash.save() {
                        Ok(()) => "Deleted.".into(),
                        Err(e) => format!("Save failed: {e}"),
                    });
                    if dash.tab == DashboardTab::Ssh {
                        dash.sync_ssh_agent();
                    }
                } else if matches!(key, KeyCode::Char('n') | KeyCode::Char('N')) {
                    dash.modal = Modal::None;
                }
            }

            Modal::AddPassword(form) => match key {
                KeyCode::Tab => {
                    form.field = (form.field + 1) % 3;
                    form.cursor = match form.field {
                        0 => form.name.chars().count(),
                        1 => form.username.chars().count(),
                        _ => form.password.chars().count(),
                    };
                }
                KeyCode::Enter => {
                    if form.field < 2 {
                        form.field += 1;
                        form.cursor = match form.field {
                            1 => form.username.chars().count(),
                            _ => form.password.chars().count(),
                        };
                    } else if !form.name.is_empty() {
                        if let Some(existing) = form
                            .editing
                            .and_then(|idx| dash.blob.passwords.get_mut(idx))
                        {
                            existing.name = form.name.clone();
                            existing.username = form.username.clone();
                            existing.password =
                                fob_core::types::SecretString::new(form.password.clone());
                            existing.modified = fob_core::vault::unix_now();
                        } else {
                            let entry = fob_core::types::PasswordEntry::new(
                                form.name.clone(),
                                form.username.clone(),
                                form.password.clone(),
                            );
                            dash.blob.passwords.push(entry);
                        }
                        dash.modal = Modal::None;
                        dash.status = Some(match dash.save() {
                            Ok(()) => "Saved.".into(),
                            Err(e) => format!("Save failed: {e}"),
                        });
                    }
                }
                KeyCode::F(2) if form.field == 2 => {
                    if let Ok(pw) = fob_core::generator::generate_password(20) {
                        form.cursor = pw.chars().count();
                        form.password = pw;
                    }
                }
                _ => {
                    let field = match form.field {
                        0 => &mut form.name,
                        1 => &mut form.username,
                        _ => &mut form.password,
                    };
                    handle_text_input(field, &mut form.cursor, key);
                }
            },

            Modal::AddNote(form) => match key {
                KeyCode::Tab => {
                    form.field = (form.field + 1) % 2;
                    form.cursor = match form.field {
                        0 => form.title.chars().count(),
                        _ => form.body.chars().count(),
                    };
                }
                KeyCode::Enter => {
                    if form.field < 1 {
                        form.field += 1;
                        form.cursor = form.body.chars().count();
                    } else if !form.title.is_empty() {
                        if let Some(existing) =
                            form.editing.and_then(|idx| dash.blob.notes.get_mut(idx))
                        {
                            existing.title = form.title.clone();
                            existing.body = fob_core::types::SecretString::new(form.body.clone());
                            existing.modified = fob_core::vault::unix_now();
                        } else {
                            let entry = fob_core::types::NoteEntry::new(
                                form.title.clone(),
                                form.body.clone(),
                            );
                            dash.blob.notes.push(entry);
                        }
                        dash.modal = Modal::None;
                        dash.status = Some(match dash.save() {
                            Ok(()) => "Saved.".into(),
                            Err(e) => format!("Save failed: {e}"),
                        });
                    }
                }
                _ => {
                    let field = match form.field {
                        0 => &mut form.title,
                        _ => &mut form.body,
                    };
                    handle_text_input(field, &mut form.cursor, key);
                }
            },

            Modal::AddTotp(form) => match key {
                KeyCode::Tab => {
                    form.field = (form.field + 1) % 3;
                    form.cursor = match form.field {
                        0 => form.issuer.chars().count(),
                        1 => form.account.chars().count(),
                        _ => form.secret.chars().count(),
                    };
                }
                KeyCode::Enter => {
                    if form.field < 2 {
                        form.field += 1;
                        form.cursor = match form.field {
                            1 => form.account.chars().count(),
                            _ => form.secret.chars().count(),
                        };
                    } else if !form.issuer.is_empty() && !form.secret.is_empty() {
                        match fob_core::totp::decode_secret(&form.secret) {
                            Ok(secret_bytes) => {
                                if let Some(existing) =
                                    form.editing.and_then(|idx| dash.blob.totps.get_mut(idx))
                                {
                                    existing.issuer = form.issuer.clone();
                                    existing.account = form.account.clone();
                                    existing.secret = fob_core::types::SecretBytes(secret_bytes);
                                } else {
                                    let entry = fob_core::types::TotpEntry::new(
                                        form.issuer.clone(),
                                        form.account.clone(),
                                        secret_bytes,
                                    );
                                    dash.blob.totps.push(entry);
                                }
                                dash.modal = Modal::None;
                                dash.status = Some(match dash.save() {
                                    Ok(()) => "Saved.".into(),
                                    Err(e) => format!("Save failed: {e}"),
                                });
                            }
                            Err(e) => dash.status = Some(format!("Invalid secret: {e}")),
                        }
                    }
                }
                _ => {
                    let field = match form.field {
                        0 => &mut form.issuer,
                        1 => &mut form.account,
                        _ => &mut form.secret,
                    };
                    handle_text_input(field, &mut form.cursor, key);
                }
            },

            Modal::AddSsh(form) => match key {
                KeyCode::Tab => {
                    form.field = (form.field + 1) % 3;
                    form.cursor = match form.field {
                        0 => form.name.chars().count(),
                        1 => form.public_key.chars().count(),
                        _ => form.private_key.chars().count(),
                    };
                }
                KeyCode::Enter => {
                    if form.field < 2 {
                        form.field += 1;
                        form.cursor = match form.field {
                            1 => form.public_key.chars().count(),
                            _ => form.private_key.chars().count(),
                        };
                    } else if !form.name.is_empty() && !form.public_key.is_empty() {
                        if let Some(idx) = form.editing {
                            match fob_core::sshkey::fingerprint(&form.public_key) {
                                Ok(fingerprint) => {
                                    let algorithm = fob_core::sshkey::algorithm(&form.public_key);
                                    if let Some(existing) = dash.blob.ssh_keys.get_mut(idx) {
                                        existing.name = form.name.clone();
                                        existing.public_key = form.public_key.clone();
                                        existing.private_key = fob_core::types::SecretString::new(
                                            form.private_key.clone(),
                                        );
                                        existing.fingerprint = fingerprint;
                                        existing.algorithm = algorithm;
                                    }
                                    dash.modal = Modal::None;
                                    dash.status = Some(match dash.save() {
                                        Ok(()) => "Saved.".into(),
                                        Err(e) => format!("Save failed: {e}"),
                                    });
                                    dash.sync_ssh_agent();
                                }
                                Err(e) => dash.status = Some(format!("Invalid public key: {e}")),
                            }
                        } else {
                            match fob_core::types::SshKeyEntry::new(
                                form.name.clone(),
                                form.public_key.clone(),
                                form.private_key.clone(),
                            ) {
                                Ok(entry) => {
                                    dash.blob.ssh_keys.push(entry);
                                    dash.modal = Modal::None;
                                    dash.status = Some(match dash.save() {
                                        Ok(()) => "Saved.".into(),
                                        Err(e) => format!("Save failed: {e}"),
                                    });
                                    dash.sync_ssh_agent();
                                }
                                Err(e) => dash.status = Some(format!("Invalid public key: {e}")),
                            }
                        }
                    }
                }
                _ => {
                    let field = match form.field {
                        0 => &mut form.name,
                        1 => &mut form.public_key,
                        _ => &mut form.private_key,
                    };
                    handle_text_input(field, &mut form.cursor, key);
                }
            },
        }
    }
}
