use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::Style,
    text::{Line, Span},
    widgets::{Block, Borders, Clear, Paragraph, Wrap},
    Frame,
};

use super::{
    accent, bold_blue, bold_red, bold_white, centered_rect, dim, hint_span, muted, sep_span, BLUE,
    GOLD, GREEN, RED, WHITE,
};
use crate::tui::state::{AppState, WizardStep};

pub(super) fn render_wizard(frame: &mut Frame, state: &AppState, step: WizardStep) {
    let area = frame.area();
    let popup = centered_rect(62, 20, area);
    frame.render_widget(Clear, popup);

    // ExistingVault is its own layout — no numbered steps / progress bar.
    if step == WizardStep::ExistingVault {
        frame.render_widget(
            Block::default()
                .title(Span::styled("  Fob Detected  ", bold_blue()))
                .borders(Borders::ALL)
                .border_style(Style::default().fg(GOLD)),
            popup,
        );
        let content = Rect::new(popup.x + 2, popup.y + 2, popup.width - 4, popup.height - 4);
        render_step_existing_vault(frame, state, content);
        return;
    }

    let (step_n, step_total, title) = match &step {
        WizardStep::ExistingVault => unreachable!(),
        WizardStep::ConfirmWipe => (1, 3, "Erase Drive"),
        WizardStep::Master => (2, 3, "Set Passphrase"),
        WizardStep::Confirm => (3, 3, "Confirm & Create"),
    };

    let filled = (step_n * 16) / step_total;
    let progress = format!("{}{}", "▓".repeat(filled), "░".repeat(16 - filled));

    frame.render_widget(
        Block::default()
            .title(Span::styled(
                format!("  Setup  {}/{}  {}  ", step_n, step_total, title),
                bold_blue(),
            ))
            .borders(Borders::ALL)
            .border_style(Style::default().fg(BLUE)),
        popup,
    );

    let bar_area = Rect::new(popup.x + 2, popup.y + 2, popup.width - 4, 1);
    frame.render_widget(
        Paragraph::new(Line::from(vec![
            Span::styled(progress, accent()),
            Span::styled(format!("  step {}/{}", step_n, step_total), muted()),
        ])),
        bar_area,
    );

    let content = Rect::new(popup.x + 2, popup.y + 4, popup.width - 4, popup.height - 6);

    match step {
        WizardStep::ExistingVault => unreachable!(),
        WizardStep::ConfirmWipe => render_step_wipe(frame, state, content),
        WizardStep::Master => render_step_master(frame, state, content),
        WizardStep::Confirm => render_step_confirm(frame, state, content),
    }
}

fn render_step_existing_vault(frame: &mut Frame, state: &AppState, area: Rect) {
    let dev_name = state
        .devices
        .get(state.selected_device)
        .map(|d| format!("{}  ({})", d.name, d.size_display()))
        .unwrap_or_else(|| "Unknown".into());

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(8), Constraint::Length(1)])
        .split(area);

    frame.render_widget(
        Paragraph::new(vec![
            Line::styled("A Fob vault is already on this drive:", muted()),
            Line::raw(""),
            Line::from(vec![Span::raw("  "), Span::styled(&dev_name, bold_white())]),
            Line::raw(""),
            Line::from(vec![
                Span::styled("  o  ", bold_blue()),
                Span::styled("Open", Style::default().fg(WHITE)),
                Span::styled("  — unlock and browse your vault", muted()),
            ]),
            Line::raw(""),
            Line::from(vec![
                Span::styled("  u  ", bold_blue()),
                Span::styled("Update", Style::default().fg(WHITE)),
                Span::styled(
                    "  — install the latest vault UI, keep your vault data",
                    muted(),
                ),
            ]),
            Line::raw(""),
            Line::from(vec![
                Span::styled("  f  ", bold_red()),
                Span::styled("Fresh setup", Style::default().fg(WHITE)),
                Span::styled("  — erase everything and start over", muted()),
            ]),
        ])
        .wrap(Wrap { trim: true }),
        chunks[0],
    );

    frame.render_widget(
        Paragraph::new(Line::from(vec![
            hint_span("o"),
            sep_span(" open  "),
            hint_span("u"),
            sep_span(" update  "),
            hint_span("f"),
            sep_span(" fresh setup  "),
            hint_span("Esc"),
            sep_span(" back"),
        ])),
        chunks[1],
    );
}

fn render_step_wipe(frame: &mut Frame, state: &AppState, area: Rect) {
    let dev_name = state
        .devices
        .get(state.selected_device)
        .map(|d| format!("{}  ({})", d.name, d.size_display()))
        .unwrap_or_else(|| "Unknown".into());

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(6), Constraint::Length(1)])
        .split(area);

    frame.render_widget(
        Paragraph::new(vec![
            Line::from(vec![
                Span::styled("WARNING  ", bold_red()),
                Span::styled("All data on this drive will be erased:", muted()),
            ]),
            Line::raw(""),
            Line::from(vec![Span::raw("  "), Span::styled(&dev_name, bold_white())]),
            Line::raw(""),
            Line::styled(
                "The drive will be formatted and a fresh encrypted vault",
                muted(),
            ),
            Line::styled("will be created. This cannot be undone.", muted()),
            Line::raw(""),
        ])
        .wrap(Wrap { trim: true }),
        chunks[0],
    );

    frame.render_widget(
        Paragraph::new(Line::from(vec![
            hint_span("y"),
            sep_span(" erase and continue  "),
            hint_span("n"),
            sep_span(" go back"),
        ])),
        chunks[1],
    );
}

fn render_step_master(frame: &mut Frame, state: &AppState, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(2),
            Constraint::Length(3),
            Constraint::Length(3),
            Constraint::Min(0),
            Constraint::Length(1),
        ])
        .split(area);

    frame.render_widget(
        Paragraph::new(vec![
            Line::styled("Choose a strong passphrase to protect your vault.", muted()),
            Line::styled("Use 5+ random words for best security.", dim()),
        ]),
        chunks[0],
    );

    let f0 = state.wizard.field == 0;
    let f1 = state.wizard.field == 1;

    let mismatch = state.wizard.mismatch_flash > 0;

    let pass_border = if f0 { Style::default().fg(BLUE) } else { dim() };
    let pass_title = if f0 {
        " ▶ Passphrase "
    } else {
        " Passphrase "
    };
    frame.render_widget(
        Paragraph::new(Span::styled(
            "●".repeat(state.wizard.main_pass.chars().count()),
            if f0 {
                Style::default().fg(WHITE)
            } else {
                dim()
            },
        ))
        .block(
            Block::default()
                .title(pass_title)
                .borders(Borders::ALL)
                .border_style(pass_border),
        ),
        chunks[1],
    );
    if f0 {
        let inner_width = chunks[1].width.saturating_sub(2);
        let x_off = (state.wizard.cursor as u16).min(inner_width.saturating_sub(1));
        frame.set_cursor_position((chunks[1].x + 1 + x_off, chunks[1].y + 1));
    }

    let conf_border = if mismatch {
        Style::default().fg(RED)
    } else if f1 {
        Style::default().fg(BLUE)
    } else {
        dim()
    };
    let conf_title = if mismatch {
        " ✗ Passphrases don't match "
    } else if f1 {
        " ▶ Confirm passphrase "
    } else {
        " Confirm passphrase "
    };
    frame.render_widget(
        Paragraph::new(Span::styled(
            "●".repeat(state.wizard.main_pass_confirm.chars().count()),
            if f1 {
                Style::default().fg(WHITE)
            } else {
                dim()
            },
        ))
        .block(
            Block::default()
                .title(conf_title)
                .borders(Borders::ALL)
                .border_style(conf_border),
        ),
        chunks[2],
    );
    if f1 {
        let inner_width = chunks[2].width.saturating_sub(2);
        let x_off = (state.wizard.cursor as u16).min(inner_width.saturating_sub(1));
        frame.set_cursor_position((chunks[2].x + 1 + x_off, chunks[2].y + 1));
    }

    frame.render_widget(
        Paragraph::new(Line::from(vec![
            hint_span("Tab"),
            sep_span(" switch field  "),
            hint_span("Enter"),
            sep_span(" continue  "),
            hint_span("Esc"),
            sep_span(" back"),
        ])),
        chunks[4],
    );
}

fn render_step_confirm(frame: &mut Frame, state: &AppState, area: Rect) {
    let dev_name = state
        .devices
        .get(state.selected_device)
        .map(|d| format!("{}  ({})", d.name, d.size_display()))
        .unwrap_or_else(|| "Unknown".into());

    let pass_len = state.wizard.main_pass.len();
    let (strength_label, strength_color) = if pass_len >= 20 {
        ("Strong", GREEN)
    } else if pass_len >= 12 {
        ("Good", GOLD)
    } else {
        ("Short — consider using a longer passphrase", RED)
    };

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(6), Constraint::Length(1)])
        .split(area);

    let (recovery_label, recovery_color) = if state.wizard.recovery_enabled {
        ("Enabled — will display a one-time recovery key", GREEN)
    } else {
        ("Disabled  (press r to enable)", WHITE)
    };

    frame.render_widget(
        Paragraph::new(vec![
            Line::styled("Ready to create your vault:", muted()),
            Line::raw(""),
            Line::from(vec![
                Span::styled("  Drive       ", muted()),
                Span::styled(&dev_name, Style::default().fg(WHITE)),
            ]),
            Line::from(vec![
                Span::styled("  Passphrase  ", muted()),
                Span::styled(strength_label, Style::default().fg(strength_color)),
            ]),
            Line::from(vec![
                Span::styled("  Recovery    ", muted()),
                Span::styled(recovery_label, Style::default().fg(recovery_color)),
            ]),
            Line::raw(""),
            Line::styled(
                "After setup, open index.html from the USB drive in your browser.",
                dim(),
            ),
        ]),
        chunks[0],
    );

    frame.render_widget(
        Paragraph::new(Line::from(vec![
            hint_span("Enter"),
            sep_span(" create vault  "),
            hint_span("r"),
            sep_span(" toggle recovery key  "),
            hint_span("Esc"),
            sep_span(" back"),
        ])),
        chunks[1],
    );
}
