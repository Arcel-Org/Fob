use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::Style,
    text::{Line, Span},
    widgets::{Block, Borders, Clear, Paragraph},
    Frame,
};

use super::{bold_blue, centered_rect, hint_span, muted, sep_span, BLUE, RED, WHITE};
use crate::tui::state::AppState;

pub(super) fn render_unlock(frame: &mut Frame, state: &AppState) {
    let area = frame.area();
    let popup = centered_rect(56, 11, area);
    frame.render_widget(Clear, popup);

    frame.render_widget(
        Block::default()
            .title(Span::styled("  Unlock Vault  ", bold_blue()))
            .borders(Borders::ALL)
            .border_style(Style::default().fg(BLUE)),
        popup,
    );

    let content = Rect::new(popup.x + 2, popup.y + 2, popup.width - 4, popup.height - 4);
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1),
            Constraint::Length(3),
            Constraint::Length(1),
            Constraint::Min(0),
            Constraint::Length(1),
        ])
        .split(content);

    frame.render_widget(
        Paragraph::new(Line::styled(
            "Enter your passphrase — main, decoy, or duress.",
            muted(),
        )),
        chunks[0],
    );

    frame.render_widget(
        Paragraph::new(Span::styled(
            "●".repeat(state.unlock.passphrase.chars().count()),
            Style::default().fg(WHITE),
        ))
        .block(
            Block::default()
                .title(" Passphrase ")
                .borders(Borders::ALL)
                .border_style(if state.unlock.error.is_some() {
                    Style::default().fg(RED)
                } else {
                    Style::default().fg(BLUE)
                }),
        ),
        chunks[1],
    );
    {
        let inner_width = chunks[1].width.saturating_sub(2);
        let x_off = (state.unlock.cursor as u16).min(inner_width.saturating_sub(1));
        frame.set_cursor_position((chunks[1].x + 1 + x_off, chunks[1].y + 1));
    }

    if let Some(err) = &state.unlock.error {
        frame.render_widget(
            Paragraph::new(Line::styled(err.as_str(), Style::default().fg(RED))),
            chunks[2],
        );
    }

    frame.render_widget(
        Paragraph::new(Line::from(vec![
            hint_span("Enter"),
            sep_span(" unlock  "),
            hint_span("Esc"),
            sep_span(" back"),
        ])),
        chunks[4],
    );
}
