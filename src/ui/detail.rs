//! Detail pane: the selected Finding as typed key/value rows plus every
//! remedy's *literal* command string. This pane is the guarantee behind spec
//! §4's promise — "the tool must never run anything the user hasn't seen
//! verbatim" — so it must render the planned command unmodified, never a
//! paraphrase, and must never clip it: commands wrap.
//!
//! `build` is pure (a `Vec<Field>`), `render` turns fields into lines; both
//! are testable without a terminal.

use std::collections::BTreeMap;
use std::sync::Arc;

use ratatui::layout::Rect;
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph, Wrap};
use ratatui::Frame;

use crate::attribution::model::{Axis, FootprintSet};
use crate::config::DeleteMode;
use crate::model::{Finding, ScannerId};
use crate::remedy::RemedyEngine;
use crate::ui::present::{self, kv, DetailCtx, Field, MetaView};
use crate::ui::{fmt, theme};

/// Per-draw detail-pane state, bundled so `draw` stays under clippy's
/// argument-count lint: the delete mode remedies are planned under, the
/// pane's own scroll offset (`J`/`K`/wheel-driven, owned by `AppState::
/// detail_scroll`), and which remedy the user chose with `e`.
pub struct DetailState {
    pub delete_mode: DeleteMode,
    pub scroll: u16,
    pub chosen_remedy: Option<usize>,
}

/// `state.scroll` is the pane's vertical scroll offset (lines) — this pane
/// is the only thing on screen that can outgrow its box (a finding's meta +
/// remedies can run to dozens of lines), so it's the one pane that scrolls.
pub fn draw(
    frame: &mut Frame,
    area: Rect,
    selected: Option<&Finding>,
    section: ScannerId,
    state: DetailState,
    footprints: &BTreeMap<Axis, Arc<FootprintSet>>,
) {
    let block = Block::default().borders(Borders::LEFT).title(" Detail ");
    let text: Vec<Line> = match selected {
        None => vec![Line::from(Span::styled(
            "Select a row to see its details.",
            Style::default().fg(Color::DarkGray),
        ))],
        Some(f) => render(
            &build_with_choice(
                f,
                section,
                state.delete_mode,
                std::time::SystemTime::now(),
                state.chosen_remedy,
                &DetailCtx { footprints },
            ),
            block.inner(area).width,
        ),
    };
    frame.render_widget(
        Paragraph::new(text)
            .block(block)
            .wrap(Wrap { trim: false })
            .scroll((state.scroll, 0)),
        area,
    );
}

/// The detail fields for `f`: generic facts, the section's typed meta rows,
/// any leftover meta keys, then the remedies. No attribution axis has
/// finished a scan in these tests, so `DetailCtx` is built from an empty
/// footprints map — fine for every section this is used to test.
#[cfg(test)]
pub fn build(
    f: &Finding,
    section: ScannerId,
    delete_mode: DeleteMode,
    now: std::time::SystemTime,
) -> Vec<Field> {
    let footprints = BTreeMap::new();
    build_with_choice(
        f,
        section,
        delete_mode,
        now,
        None,
        &DetailCtx {
            footprints: &footprints,
        },
    )
}

/// `build`, marking the remedy the user chose with `e` (▶) and labelling
/// alternatives that never run unless chosen.
pub fn build_with_choice(
    f: &Finding,
    section: ScannerId,
    delete_mode: DeleteMode,
    now: std::time::SystemTime,
    chosen: Option<usize>,
    ctx: &DetailCtx,
) -> Vec<Field> {
    let mut fields = vec![Field::Header(""), Field::Text(f.title.clone())];
    if !f.detail.is_empty() && f.detail != f.title {
        fields.push(Field::Text(f.detail.clone()));
    }
    fields.push(Field::Blank);
    if let Some(p) = &f.path {
        fields.push(kv("Path", fmt::abbrev_home(p)));
    }
    if let Some(b) = f.size_bytes {
        fields.push(kv("Size", fmt::bytes(b)));
    }
    if let Some(t) = f.last_used {
        fields.push(kv(
            "Last used",
            format!("{} ({})", fmt::humanize_ago(t, now), fmt::iso_date(t)),
        ));
    }
    fields.push(present::kv_styled(
        "Severity",
        theme::severity_label(f.severity),
        theme::severity_color(f.severity),
    ));
    if let Some(provenance) = &f.provenance {
        fields.push(kv("Source", provenance.clone()));
    }
    if let Some(coverage) = &f.coverage {
        fields.push(kv("Coverage", coverage.clone()));
    }

    if f.meta.is_object() {
        let mut view = MetaView::new(&f.meta);
        let mut typed = (present::presenter(section).detail)(f, &mut view, ctx);
        typed.extend(present::generic_fields(&view.remaining()));
        if !typed.is_empty() {
            fields.push(Field::Blank);
            fields.push(Field::Header("Details"));
            fields.extend(typed);
        }
    }

    if !f.remedies.is_empty() {
        fields.push(Field::Blank);
        fields.push(Field::Header("Remedies"));
        // Plan through the RemedyEngine so the string shown matches what
        // would actually run — under `--rm`, a Trash remedy displays as
        // `rm -rf …`.
        let engine = RemedyEngine::new(delete_mode);
        let primary_runs: Vec<bool> = {
            let chosen_runs = crate::ui::marking::execution_remedies(f, chosen);
            f.remedies
                .iter()
                .map(|r| chosen_runs.iter().any(|c| std::ptr::eq(*c, r)))
                .collect()
        };
        for (i, r) in f.remedies.iter().enumerate() {
            let action = engine.plan_one(f.id, r);
            let marker = if primary_runs[i] { "▶" } else { " " };
            let alt = if r.alternative {
                " (alternative — e to choose)"
            } else {
                ""
            };
            fields.push(Field::Command {
                label: format!("{marker} {}. {}{alt}", i + 1, r.label),
                rendered: action.rendered,
                destructive: r.destructive,
            });
        }
        if let Some(g) = f.remedies.iter().find_map(|r| r.guard.as_ref()) {
            let _ = g;
            fields.push(Field::Text(
                "Guarded: every target is re-checked against a fresh scan right before it runs."
                    .into(),
            ));
        }
    }
    fields
}

/// Fields → styled lines for a pane `width` cells wide. Labels are padded to
/// a common width so values line up; a value that wouldn't fit beside its
/// label drops to its own indented line (so long paths wrap cleanly instead
/// of under the label); commands take their own line prefixed with `$`.
pub fn render(fields: &[Field], width: u16) -> Vec<Line<'static>> {
    use unicode_width::UnicodeWidthStr;
    let label_width = fields
        .iter()
        .filter_map(|f| match f {
            Field::Kv { label, .. } => Some(label.chars().count()),
            _ => None,
        })
        .max()
        .unwrap_or(0)
        .min(18);
    let dim = Style::default().fg(Color::DarkGray);
    let mut lines = Vec::new();
    let mut first_text = true;
    for field in fields {
        match field {
            Field::Header("") => {}
            Field::Header(h) => lines.push(Line::from(Span::styled(
                (*h).to_string(),
                Style::default().add_modifier(Modifier::BOLD),
            ))),
            Field::Blank => lines.push(Line::from("")),
            Field::Text(t) => {
                // The first text is the title.
                let style = if first_text {
                    first_text = false;
                    Style::default().add_modifier(Modifier::BOLD)
                } else {
                    Style::default()
                };
                lines.push(Line::from(Span::styled(t.clone(), style)));
            }
            Field::Kv {
                label,
                value,
                style,
            } => {
                let value_style = style.unwrap_or_default();
                if label_width + 2 + value.width() <= width as usize {
                    lines.push(Line::from(vec![
                        Span::styled(format!("{label:<label_width$}  "), dim),
                        Span::styled(value.clone(), value_style),
                    ]));
                } else {
                    lines.push(Line::from(Span::styled(label.to_string(), dim)));
                    lines.push(Line::from(Span::styled(format!("  {value}"), value_style)));
                }
            }
            Field::Command {
                label,
                rendered,
                destructive,
            } => {
                lines.push(Line::from(vec![
                    Span::raw(format!("{label} ")),
                    Span::styled(
                        if *destructive { "(destructive)" } else { "" },
                        Style::default().fg(Color::Red),
                    ),
                ]));
                lines.push(Line::from(vec![
                    Span::styled("  $ ", dim),
                    Span::styled(
                        rendered.clone(),
                        Style::default().fg(theme::remedy_color(*destructive)),
                    ),
                ]));
            }
        }
    }
    lines
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, SystemTime};

    use super::*;
    use crate::model::{FindingKind, Remedy, RemedyCommand, Severity};

    fn text_of(lines: &[Line<'_>]) -> String {
        lines
            .iter()
            .map(|l| {
                l.spans
                    .iter()
                    .map(|s| s.content.as_ref())
                    .collect::<String>()
            })
            .collect::<Vec<_>>()
            .join("\n")
    }

    #[test]
    fn no_since_epoch_and_literal_command_visible() {
        let long = "/Users/dev/Library/Application Support/Some Vendor/With Spaces/and/a/very/long/nested/path/that/keeps/going/node_modules";
        let f = Finding::new(FindingKind::BuildArtifact, long, "node_modules — deep")
            .path(long)
            .size(12345678)
            .severity(Severity::Reclaimable)
            .last_used(SystemTime::now() - Duration::from_secs(3 * 86400))
            .meta(serde_json::json!({"group": "node_modules", "artifact": "node_modules", "stale": true}))
            .remedy(Remedy {
                label: "Move to Trash".into(),
                command: RemedyCommand::Trash { path: long.into() },
                reclaims_bytes: Some(12345678),
                destructive: true,
                alternative: false,
                guard: None,
            });
        let fields = build(&f, ScannerId::Fs, DeleteMode::Rm, SystemTime::now());
        let text = text_of(&render(&fields, 60));

        assert!(!text.contains("since epoch"), "{text}");
        assert!(!text.contains('{'), "no JSON dump: {text}");
        assert!(text.contains("3d ago"), "{text}");
        assert!(text.contains("Artifact"), "{text}");
        assert!(text.contains("Stale"), "{text}");
        // The literal command, byte for byte, in rm mode.
        let expected = RemedyEngine::new(DeleteMode::Rm)
            .plan_one(f.id, &f.remedies[0])
            .rendered;
        assert!(expected.starts_with("rm -rf"), "{expected}");
        assert!(text.contains(&expected), "{text}");
    }

    #[test]
    fn unknown_meta_keys_still_render_generically() {
        let f = Finding::new(FindingKind::LaunchdItem, "/x.plist", "com.x")
            .meta(serde_json::json!({"label": "com.x", "brand_new_key": "surprise"}));
        let text = text_of(&render(
            &build(&f, ScannerId::Launchd, DeleteMode::Trash, SystemTime::now()),
            80,
        ));
        assert!(text.contains("Brand new key  surprise"), "{text}");
    }

    #[test]
    fn long_values_drop_to_their_own_line() {
        let fields = vec![kv("Path", "x".repeat(70)), kv("Size", "1 MiB")];
        let lines = render(&fields, 40);
        let text = text_of(&lines);
        assert!(text.contains("Path\n  xxx"), "{text}");
        assert!(text.contains("Size  1 MiB"), "{text}");
    }
}
