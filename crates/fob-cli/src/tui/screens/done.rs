use ratatui::{
    style::Style,
    text::{Line, Span},
    widgets::{Block, Borders, Clear, Paragraph},
    Frame,
};

use super::{bold_blue, centered_rect, dim, muted, BLUE, GOLD, WHITE};
use crate::tui::state::AppState;

pub(super) fn render_done(frame: &mut Frame, state: &AppState) {
    let area = frame.area();

    let (headline, sub) = if state.update_mode {
        ("  Vault UI updated.", "  Your vault data is untouched.")
    } else {
        (
            "  Vault created successfully.",
            "  Your USB drive is ready to use.",
        )
    };

    let mut lines = vec![
        Line::raw(""),
        Line::from(vec![Span::styled(headline, bold_blue())]),
        Line::raw(""),
        Line::styled(sub, Style::default().fg(WHITE)),
        Line::raw(""),
        Line::styled("  Next steps:", muted()),
        Line::styled("    1.  Eject the USB drive safely.", muted()),
        Line::styled("    2.  Plug it in to any computer.", muted()),
        Line::styled("    3.  Open  index.html  in your browser.", muted()),
    ];

    let recovery_key = state.wizard.recovery_key_display.as_deref();
    if let Some(key) = recovery_key {
        lines.push(Line::raw(""));
        lines.push(Line::styled(
            "  ── Recovery key — write this down now ──",
            Style::default().fg(GOLD),
        ));
        lines.push(Line::styled(
            "  Shown only once. It unlocks this vault without your",
            muted(),
        ));
        lines.push(Line::styled(
            "  passphrase (run `fob recover`). Store it somewhere",
            muted(),
        ));
        lines.push(Line::styled("  other than this USB drive.", muted()));
        lines.push(Line::raw(""));
        for chunk in key.as_bytes().chunks(40) {
            let s = std::str::from_utf8(chunk).unwrap_or("");
            lines.push(Line::from(vec![
                Span::raw("  "),
                Span::styled(s.to_string(), Style::default().fg(GOLD)),
            ]));
        }
    }

    lines.push(Line::raw(""));
    lines.push(Line::from(vec![Span::styled(
        "  Press any key to exit.",
        dim(),
    )]));

    let height = (lines.len() as u16 + 2).min(area.height);
    let popup = centered_rect(if recovery_key.is_some() { 60 } else { 56 }, height, area);
    frame.render_widget(Clear, popup);

    frame.render_widget(
        Paragraph::new(lines).block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(BLUE)),
        ),
        popup,
    );
}
