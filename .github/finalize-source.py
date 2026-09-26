"""Apply reviewed rendering fixes once; CI deletes this script after formatting."""
from pathlib import Path
files = {}
def get(path):
    if path not in files: files[path] = Path(path).read_text()
    return files[path]
def replace(path, before, after):
    text = get(path)
    assert text.count(before) == 1, (path, before[:100], text.count(before))
    files[path] = text.replace(before, after)
g = 'src/gui.rs'
replace(g, '        cc.egui_ctx.set_style(style);', '''        style.text_styles.insert(egui::TextStyle::Small, egui::FontId::proportional(12.0));
        style.text_styles.insert(egui::TextStyle::Monospace, egui::FontId::monospace(14.0));
        cc.egui_ctx.set_style(style);''')
replace(g, '            .show(ui, body);', '''            .show(ui, |ui| {
                ui.set_min_width(ui.available_width());
                body(ui);
            });''')
replace(g, 'ui.collapsing("Details", |ui| {', 'egui::CollapsingHeader::new("Details").id_salt(("activity", &job.id)).show(ui, |ui| {')
p = 'src/gui/review.rs'
replace(p, '            egui::ScrollArea::vertical().id_salt("review_details")', '''            // A ScrollArea inherits its parent's layout. Explicitly leave the
            // outer horizontal queue layout before rendering stacked details.
            ui.allocate_ui_with_layout(Vec2::new(ui.available_width(), height), egui::Layout::top_down(egui::Align::Min), |ui| {
            egui::ScrollArea::vertical().id_salt("review_details")''')
replace(p, '        });\n    }\n}', '            });\n        });\n    }\n}')
replace(p, 'let body_height = (height - 270.0).clamp(170.0, 310.0);', 'let body_height = (height - 320.0).clamp(140.0, 250.0);')
assert get(p).count('ui.set_min_height(body_height + 150.0);') == 2
files[p] = get(p).replace('ui.set_min_height(body_height + 150.0);', 'ui.set_min_height(body_height + 125.0);')
replace(p, '                ui.columns(2, |cols| {', '                let cards = ui.scope(|ui| { ui.columns(2, |cols| {')
replace(p, '                });\n                if !bound {', '                }); }).response;\n                if !bound {')
replace(p, '\n                ui.horizontal_wrapped(|ui| {', '\n                let actions = ui.horizontal_wrapped(|ui| {')
replace(p, '                });\n                if !s.settings.sending_enabled {', '''                }).response;
                if self.screenshot.is_some() && self.frames > 10 {
                    assert!(review_actions_visible(cards.rect, actions.rect, ui.clip_rect()),
                        "Review controls are not below the cards and visible: cards={:?}, actions={:?}, viewport={:?}",
                        cards.rect, actions.rect, ui.clip_rect());
                }
                if !s.settings.sending_enabled {''')
files[p] = get(p) + '''
/// Actual screenshot runs call this on rendered widget rectangles, not mock coordinates.
fn review_actions_visible(cards: egui::Rect, actions: egui::Rect, clip: egui::Rect) -> bool {
    actions.top() >= cards.bottom() - 1.0 && clip.contains_rect(actions.shrink(0.5))
}
#[cfg(test)]
mod layout_tests {
    use super::*;
    #[test]
    fn actions_must_be_below_cards_and_inside_viewport() {
        let cards = egui::Rect::from_min_max(egui::pos2(0.0, 0.0), egui::pos2(500.0, 300.0));
        let clip = egui::Rect::from_min_max(egui::pos2(0.0, 0.0), egui::pos2(500.0, 500.0));
        let below = egui::Rect::from_min_max(egui::pos2(0.0, 320.0), egui::pos2(450.0, 360.0));
        assert!(review_actions_visible(cards, below, clip));
        assert!(!review_actions_visible(cards, below.translate(egui::vec2(600.0, 0.0)), clip));
        assert!(!review_actions_visible(cards, below.translate(egui::vec2(0.0, -100.0)), clip));
        assert!(!review_actions_visible(cards, below.translate(egui::vec2(0.0, 200.0)), clip));
    }
}
'''
for path, text in files.items(): Path(path).write_text(text)
