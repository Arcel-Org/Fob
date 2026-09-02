use ratatui::{
    text::{Line, Span},
    widgets::{Block, Borders, Paragraph},
    Frame,
};

use super::{accent, bold_blue, centered_rect, dim, muted};
use crate::tui::state::AppState;

pub(super) fn render_boot(frame: &mut Frame, state: &AppState) {
    let area = frame.area();
    let popup = centered_rect(36, 8, area);

    let dots = match (state.tick / 8) % 4 {
        0 => "   ",
        1 => ".  ",
        2 => ".. ",
        _ => "...",
    };

    frame.render_widget(
        Paragraph::new(vec![
            Line::raw(""),
            Line::from(vec![
                Span::styled("  FOB", bold_blue()),
                Span::styled("  ·  Fob", muted()),
            ]),
            Line::raw(""),
            Line::styled("  Encrypted USB Security Vault", muted()),
            Line::raw(""),
            Line::from(vec![
                Span::styled("  Scanning for USB drives", muted()),
                Span::styled(dots, accent()),
            ]),
        ])
        .block(Block::default().borders(Borders::ALL).border_style(dim())),
        popup,
    );
}
