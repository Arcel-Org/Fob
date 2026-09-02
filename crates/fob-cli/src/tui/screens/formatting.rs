use ratatui::{
    style::Style,
    text::{Line, Span},
    widgets::{Block, Borders, Clear, Paragraph},
    Frame,
};

use super::{accent, centered_rect, dim, muted, BLUE, WHITE};
use crate::tui::state::AppState;

pub(super) fn render_formatting(frame: &mut Frame, state: &AppState) {
    let area = frame.area();
    let popup = centered_rect(44, 8, area);
    frame.render_widget(Clear, popup);

    let spinner = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];
    let s = spinner[(state.tick as usize / 2) % spinner.len()];

    let dev_name = state
        .devices
        .get(state.selected_device)
        .map(|d| format!("{}  ({})", d.name, d.size_display()))
        .unwrap_or_else(|| "drive".into());

    frame.render_widget(
        Paragraph::new(vec![
            Line::raw(""),
            Line::from(vec![
                Span::styled(format!("  {} ", s), accent()),
                Span::styled(
                    "Formatting drive, please wait...",
                    Style::default().fg(WHITE),
                ),
            ]),
            Line::raw(""),
            Line::from(vec![Span::raw("  "), Span::styled(&dev_name, muted())]),
            Line::raw(""),
            Line::styled("  This may take up to 30 seconds.", dim()),
        ])
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(BLUE)),
        ),
        popup,
    );
}
