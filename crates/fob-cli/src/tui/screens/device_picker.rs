use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::Style,
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem, ListState, Paragraph},
    Frame,
};

use super::{accent, bold_blue, bold_white, dim, hint_span, muted, sep_span, GOLD};
use crate::tui::state::AppState;

pub(super) fn render_device_picker(frame: &mut Frame, state: &AppState) {
    let area = frame.area();

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(4),
            Constraint::Min(4),
            Constraint::Length(1),
        ])
        .split(area);

    // Header
    frame.render_widget(
        Paragraph::new(vec![
            Line::raw(""),
            Line::from(vec![
                Span::styled("  FOB", bold_blue()),
                Span::styled("  —  USB Setup", muted()),
            ]),
            Line::styled(
                "  Select a USB drive to set up as your security vault.",
                muted(),
            ),
        ]),
        chunks[0],
    );

    // Drive list
    let items: Vec<ListItem> = state
        .devices
        .iter()
        .enumerate()
        .map(|(i, dev)| {
            let selected = i == state.selected_device;
            let name_style = if selected { bold_white() } else { muted() };
            let prefix = if selected {
                Span::styled("  ▶ ", accent())
            } else {
                Span::styled("    ", dim())
            };

            let vault_tag = if dev.has_fob_vault {
                Span::styled("  [vault present]", Style::default().fg(GOLD))
            } else {
                Span::styled("  [new drive]", dim())
            };

            ListItem::new(vec![
                Line::from(vec![
                    prefix.clone(),
                    Span::styled(format!("{:<28}", dev.name), name_style),
                    Span::styled(format!("{:>8}", dev.size_display()), muted()),
                    vault_tag,
                ]),
                Line::from(vec![
                    Span::raw("      "),
                    Span::styled(dev.path.display().to_string(), dim()),
                ]),
                Line::raw(""),
            ])
        })
        .collect();

    let is_empty = items.is_empty();
    let mut ls = ListState::default();
    if !is_empty {
        ls.select(Some(state.selected_device));
    }

    frame.render_stateful_widget(
        List::new(items)
            .block(
                Block::default()
                    .title(Span::styled("  USB DRIVES ", bold_blue()))
                    .borders(Borders::ALL)
                    .border_style(dim()),
            )
            .highlight_style(Style::default()),
        chunks[1],
        &mut ls,
    );

    if is_empty {
        frame.render_widget(
            Paragraph::new(vec![
                Line::raw(""),
                Line::styled("  No USB drives detected.", muted()),
                Line::styled("  Plug one in, then press r to rescan.", dim()),
            ]),
            Rect::new(
                chunks[1].x + 1,
                chunks[1].y + 1,
                chunks[1].width.saturating_sub(2),
                chunks[1].height.saturating_sub(2),
            ),
        );
    }

    // Hint bar
    let hint = if is_empty {
        Line::from(vec![
            hint_span("r"),
            sep_span(" rescan  "),
            hint_span("q"),
            sep_span(" quit"),
        ])
    } else {
        Line::from(vec![
            hint_span("↑/↓"),
            sep_span(" select  "),
            hint_span("Enter"),
            sep_span(" set up this drive  "),
            hint_span("r"),
            sep_span(" rescan  "),
            hint_span("q"),
            sep_span(" quit"),
        ])
    };
    frame.render_widget(Paragraph::new(hint), chunks[2]);
}
