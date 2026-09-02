use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Clear, List, ListItem, ListState, Paragraph, Wrap},
    Frame,
};

use super::{
    bold_blue, bold_red, bold_white, centered_rect, dim, hint_span, muted, sep_span, BLUE, GREEN,
    RED, WHITE,
};
use crate::tui::state::{AppState, DashboardState, DashboardTab, Modal};

fn mask(s: &str, reveal: bool) -> String {
    if reveal {
        s.to_string()
    } else {
        "•".repeat(s.chars().count().clamp(4, 32))
    }
}

pub(super) fn render_dashboard(frame: &mut Frame, state: &AppState) {
    let Some(dash) = state.dashboard.as_ref() else {
        return;
    };
    let area = frame.area();

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(2),
            Constraint::Min(6),
            Constraint::Length(1),
        ])
        .split(area);

    // Tab bar.
    let tabs: Vec<Span> = DashboardTab::ALL
        .iter()
        .flat_map(|t| {
            let active = *t == dash.tab;
            let label = format!(" {} ", t.label());
            vec![
                Span::styled(
                    label,
                    if active {
                        Style::default()
                            .fg(WHITE)
                            .bg(Color::Rgb(30, 60, 140))
                            .add_modifier(Modifier::BOLD)
                    } else {
                        muted()
                    },
                ),
                Span::raw(" "),
            ]
        })
        .collect();

    let header_line = if dash.tab == DashboardTab::Ssh {
        let mut spans = tabs;
        match &dash.ssh_agent {
            Some(agent) => {
                spans.push(Span::styled("   Agent: ", muted()));
                spans.push(Span::styled(
                    agent.socket_path().display().to_string(),
                    Style::default().fg(GREEN),
                ));
            }
            None => spans.push(Span::styled("   Agent: not running", dim())),
        }
        Line::from(spans)
    } else {
        Line::from(tabs)
    };
    frame.render_widget(Paragraph::new(header_line), chunks[0]);

    let body = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(38), Constraint::Percentage(62)])
        .split(chunks[1]);

    render_dashboard_list(frame, dash, body[0]);
    render_dashboard_detail(frame, dash, body[1]);

    // Footer hint / status bar.
    let footer = if let Some(status) = &dash.status {
        Line::styled(format!("  {status}"), Style::default().fg(GREEN))
    } else {
        Line::from(vec![
            hint_span("↑/↓"),
            sep_span(" select  "),
            hint_span("Tab"),
            sep_span(" category  "),
            hint_span("a"),
            sep_span(" add  "),
            hint_span("e"),
            sep_span(" edit  "),
            hint_span("d"),
            sep_span(" delete  "),
            hint_span("r"),
            sep_span(" reveal  "),
            hint_span("c"),
            sep_span(" copy  "),
            hint_span("q"),
            sep_span(" lock"),
        ])
    };
    frame.render_widget(Paragraph::new(footer), chunks[2]);

    if !matches!(dash.modal, Modal::None) {
        render_dashboard_modal(frame, dash, area);
    }
}

fn render_dashboard_list(frame: &mut Frame, dash: &DashboardState, area: Rect) {
    let items: Vec<ListItem> = match dash.tab {
        DashboardTab::Passwords => dash
            .blob
            .passwords
            .iter()
            .map(|e| ListItem::new(format!("{}  ({})", e.name, e.username)))
            .collect(),
        DashboardTab::Totp => dash
            .blob
            .totps
            .iter()
            .map(|e| ListItem::new(format!("{}  ({})", e.issuer, e.account)))
            .collect(),
        DashboardTab::Ssh => dash
            .blob
            .ssh_keys
            .iter()
            .map(|e| ListItem::new(format!("{}  [{:?}]", e.name, e.algorithm)))
            .collect(),
        DashboardTab::Notes => dash
            .blob
            .notes
            .iter()
            .map(|e| ListItem::new(e.title.clone()))
            .collect(),
    };

    let empty = items.is_empty();
    let mut ls = ListState::default();
    if !empty {
        ls.select(Some(dash.selected));
    }

    frame.render_stateful_widget(
        List::new(items)
            .block(
                Block::default()
                    .title(Span::styled(
                        format!("  {}  ", dash.tab.label()),
                        bold_blue(),
                    ))
                    .borders(Borders::ALL)
                    .border_style(dim()),
            )
            .highlight_style(Style::default().fg(WHITE).bg(Color::Rgb(30, 40, 60))),
        area,
        &mut ls,
    );

    if empty {
        frame.render_widget(
            Paragraph::new(Line::styled(
                "  Nothing here yet — press a to add one.",
                dim(),
            )),
            Rect::new(area.x + 1, area.y + 1, area.width.saturating_sub(2), 1),
        );
    }
}

fn render_dashboard_detail(frame: &mut Frame, dash: &DashboardState, area: Rect) {
    let block = Block::default()
        .title(Span::styled("  Detail  ", bold_blue()))
        .borders(Borders::ALL)
        .border_style(dim());
    frame.render_widget(block, area);
    let inner = Rect::new(
        area.x + 2,
        area.y + 1,
        area.width.saturating_sub(4),
        area.height.saturating_sub(2),
    );

    let lines: Vec<Line> = match dash.tab {
        DashboardTab::Passwords => match dash.blob.passwords.get(dash.selected) {
            Some(e) => vec![
                Line::from(vec![
                    Span::styled("Name      ", muted()),
                    Span::styled(&e.name, bold_white()),
                ]),
                Line::from(vec![
                    Span::styled("Username  ", muted()),
                    Span::styled(&e.username, Style::default().fg(WHITE)),
                ]),
                Line::from(vec![
                    Span::styled("Password  ", muted()),
                    Span::styled(
                        mask(e.password.expose(), dash.reveal),
                        Style::default().fg(WHITE),
                    ),
                ]),
            ],
            None => vec![],
        },
        DashboardTab::Totp => match dash.blob.totps.get(dash.selected) {
            Some(e) => {
                let mut lines = vec![
                    Line::from(vec![
                        Span::styled("Issuer   ", muted()),
                        Span::styled(&e.issuer, bold_white()),
                    ]),
                    Line::from(vec![
                        Span::styled("Account  ", muted()),
                        Span::styled(&e.account, Style::default().fg(WHITE)),
                    ]),
                ];
                if dash.reveal {
                    match fob_core::totp::generate_now(e) {
                        Ok(code) => {
                            let remaining =
                                fob_core::totp::seconds_remaining(e.period).unwrap_or(0);
                            lines.push(Line::from(vec![
                                Span::styled("Code     ", muted()),
                                Span::styled(
                                    code,
                                    Style::default().fg(GREEN).add_modifier(Modifier::BOLD),
                                ),
                                Span::styled(format!("   ({remaining}s)"), dim()),
                            ]));
                        }
                        Err(e) => lines.push(Line::styled(
                            format!("Code error: {e}"),
                            Style::default().fg(RED),
                        )),
                    }
                } else {
                    lines.push(Line::styled("Code      press r to reveal", dim()));
                }
                lines
            }
            None => vec![],
        },
        DashboardTab::Ssh => match dash.blob.ssh_keys.get(dash.selected) {
            Some(e) => vec![
                Line::from(vec![
                    Span::styled("Name         ", muted()),
                    Span::styled(&e.name, bold_white()),
                ]),
                Line::from(vec![
                    Span::styled("Algorithm    ", muted()),
                    Span::styled(format!("{:?}", e.algorithm), Style::default().fg(WHITE)),
                ]),
                Line::from(vec![
                    Span::styled("Fingerprint  ", muted()),
                    Span::styled(&e.fingerprint, Style::default().fg(WHITE)),
                ]),
                Line::from(vec![
                    Span::styled("Public key   ", muted()),
                    Span::styled(&e.public_key, dim()),
                ]),
                Line::from(vec![
                    Span::styled("Private key  ", muted()),
                    Span::styled(
                        mask(e.private_key.expose(), dash.reveal),
                        Style::default().fg(WHITE),
                    ),
                ]),
            ],
            None => vec![],
        },
        DashboardTab::Notes => match dash.blob.notes.get(dash.selected) {
            Some(e) => vec![
                Line::from(vec![
                    Span::styled("Title  ", muted()),
                    Span::styled(&e.title, bold_white()),
                ]),
                Line::raw(""),
                Line::styled(
                    mask(e.body.expose(), dash.reveal),
                    Style::default().fg(WHITE),
                ),
            ],
            None => vec![],
        },
    };

    frame.render_widget(Paragraph::new(lines).wrap(Wrap { trim: true }), inner);
}

fn render_dashboard_modal(frame: &mut Frame, dash: &DashboardState, area: Rect) {
    match &dash.modal {
        Modal::None => {}
        Modal::ConfirmDelete => {
            let popup = centered_rect(48, 7, area);
            frame.render_widget(Clear, popup);
            frame.render_widget(
                Paragraph::new(vec![
                    Line::raw(""),
                    Line::styled(
                        "  Delete this entry? This cannot be undone.",
                        Style::default().fg(WHITE),
                    ),
                    Line::raw(""),
                    Line::from(vec![
                        hint_span("y"),
                        sep_span(" delete  "),
                        hint_span("n"),
                        sep_span(" cancel"),
                    ]),
                ])
                .block(
                    Block::default()
                        .title(Span::styled("  Confirm Delete  ", bold_red()))
                        .borders(Borders::ALL)
                        .border_style(Style::default().fg(RED)),
                ),
                popup,
            );
        }
        Modal::AddPassword(form) => {
            // height 13, not 11: 3 fields (Length(3) each = 9) + the Min(0)
            // gap + the Length(1) hint footer need at least 10 content rows,
            // which needs at least 12 popup rows once the 2 border rows are
            // added — 11 was clipping the footer (including the F2 hint)
            // entirely off the bottom, caught by a TestBackend render test.
            // Width 72, not 56: this is the one modal with the extra "F2
            // generate" hint, and the footer line (base hints + F2 hint)
            // doesn't fit the narrower width the other modals use — it was
            // being silently truncated off the right edge.
            let popup = centered_rect(72, 13, area);
            frame.render_widget(Clear, popup);
            render_form(
                frame,
                popup,
                if form.editing.is_some() {
                    "Edit Password"
                } else {
                    "Add Password"
                },
                form.cursor,
                &[
                    ("Name", &form.name, form.field == 0, false),
                    ("Username", &form.username, form.field == 1, false),
                    ("Password", &form.password, form.field == 2, true),
                ],
                Some(("F2", "generate")),
            );
        }
        Modal::AddNote(form) => {
            let popup = centered_rect(56, 11, area);
            frame.render_widget(Clear, popup);
            render_form(
                frame,
                popup,
                if form.editing.is_some() {
                    "Edit Note"
                } else {
                    "Add Note"
                },
                form.cursor,
                &[
                    ("Title", &form.title, form.field == 0, false),
                    ("Body", &form.body, form.field == 1, false),
                ],
                None,
            );
        }
        Modal::AddTotp(form) => {
            // Same fix as AddPassword above — 3 fields need popup height 13,
            // not 11, or the hint footer is clipped off entirely.
            let popup = centered_rect(56, 13, area);
            frame.render_widget(Clear, popup);
            render_form(
                frame,
                popup,
                if form.editing.is_some() {
                    "Edit TOTP (base32 secret)"
                } else {
                    "Add TOTP (base32 secret)"
                },
                form.cursor,
                &[
                    ("Issuer", &form.issuer, form.field == 0, false),
                    ("Account", &form.account, form.field == 1, false),
                    ("Secret", &form.secret, form.field == 2, true),
                ],
                None,
            );
        }
        Modal::AddSsh(form) => {
            let popup = centered_rect(64, 13, area);
            frame.render_widget(Clear, popup);
            render_form(
                frame,
                popup,
                if form.editing.is_some() {
                    "Edit SSH Key"
                } else {
                    "Import SSH Key"
                },
                form.cursor,
                &[
                    ("Name", &form.name, form.field == 0, false),
                    ("Public key", &form.public_key, form.field == 1, false),
                    ("Private key", &form.private_key, form.field == 2, true),
                ],
                None,
            );
        }
    }
}

/// Shared renderer for the add-entry modals: a title bar, one bordered field
/// per row (masked if `secret`), and a fixed hint footer. `cursor` is the
/// char position within whichever field is currently active.
fn render_form(
    frame: &mut Frame,
    popup: Rect,
    title: &str,
    cursor: usize,
    fields: &[(&str, &str, bool, bool)],
    extra_hint: Option<(&str, &str)>,
) {
    frame.render_widget(
        Block::default()
            .title(Span::styled(format!("  {title}  "), bold_blue()))
            .borders(Borders::ALL)
            .border_style(Style::default().fg(BLUE)),
        popup,
    );

    let mut constraints: Vec<Constraint> = fields.iter().map(|_| Constraint::Length(3)).collect();
    constraints.push(Constraint::Min(0));
    constraints.push(Constraint::Length(1));

    let content = Rect::new(popup.x + 2, popup.y + 1, popup.width - 4, popup.height - 2);
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints(constraints)
        .split(content);

    for (i, (label, value, active, secret)) in fields.iter().enumerate() {
        let display = if *secret {
            "●".repeat(value.chars().count())
        } else {
            (*value).to_string()
        };
        frame.render_widget(
            Paragraph::new(Span::styled(
                display,
                if *active {
                    Style::default().fg(WHITE)
                } else {
                    dim()
                },
            ))
            .block(
                Block::default()
                    .title(format!(" {label} "))
                    .borders(Borders::ALL)
                    .border_style(if *active {
                        Style::default().fg(BLUE)
                    } else {
                        dim()
                    }),
            ),
            chunks[i],
        );
        if *active {
            let inner_width = chunks[i].width.saturating_sub(2);
            let x_off = (cursor as u16).min(inner_width.saturating_sub(1));
            frame.set_cursor_position((chunks[i].x + 1 + x_off, chunks[i].y + 1));
        }
    }

    let extra_desc = extra_hint.map(|(_, desc)| format!(" {desc}"));
    let mut hints = vec![
        hint_span("Tab"),
        sep_span(" next field  "),
        hint_span("Enter"),
        sep_span(" next / save  "),
        hint_span("Esc"),
        sep_span(" cancel"),
    ];
    if let Some((key, _)) = extra_hint {
        hints.push(sep_span("  "));
        hints.push(hint_span(key));
        hints.push(sep_span(extra_desc.as_deref().unwrap()));
    }
    frame.render_widget(Paragraph::new(Line::from(hints)), chunks[fields.len() + 1]);
}
