use ratatui::{
    style::Style,
    text::Span,
    widgets::{Block, Borders, Clear, Paragraph, Wrap},
    Frame,
};

use super::{bold_red, centered_rect, muted, RED};

pub(super) fn render_error(frame: &mut Frame, msg: &str) {
    let area = frame.area();
    let popup = centered_rect(60, 10, area);
    frame.render_widget(Clear, popup);

    frame.render_widget(
        Paragraph::new(format!("\n  {msg}\n\n  Press any key to exit."))
            .block(
                Block::default()
                    .title(Span::styled("  Error  ", bold_red()))
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(RED)),
            )
            .wrap(Wrap { trim: true })
            .style(muted()),
        popup,
    );
}
