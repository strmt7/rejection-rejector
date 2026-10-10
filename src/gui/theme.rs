//! Design tokens for the desktop interface.
//!
//! Every colour, type size and layout scale used by the GUI is declared here
//! as a named, documented token so surfaces stay visually homogeneous and
//! palette changes are reviewable in one place. `apply` installs the tokens
//! into an egui style; the tests pin accessibility contrast invariants so a
//! palette change that harms readability fails the suite.

use eframe::egui::{self, Color32, FontId, TextStyle, Vec2};

/// Application background (deepest surface).
pub(crate) const BG: Color32 = Color32::from_rgb(15, 20, 28);
/// Raised panel and window surface.
pub(crate) const PANEL: Color32 = Color32::from_rgb(22, 29, 39);
/// Hairline borders and separators.
pub(crate) const LINE: Color32 = Color32::from_rgb(47, 59, 74);
/// Primary body text.
pub(crate) const TEXT: Color32 = Color32::from_rgb(222, 231, 240);
/// Accent for primary actions and selection.
pub(crate) const MINT: Color32 = Color32::from_rgb(103, 225, 186);
/// Secondary/de-emphasised text and labels.
pub(crate) const MUTED: Color32 = Color32::from_rgb(150, 167, 187);
/// Caution and held-state messaging.
pub(crate) const AMBER: Color32 = Color32::from_rgb(245, 193, 103);
/// Inactive widget fill.
pub(crate) const WIDGET_INACTIVE: Color32 = Color32::from_rgb(34, 44, 58);
/// Hovered widget fill.
pub(crate) const WIDGET_HOVER: Color32 = Color32::from_rgb(47, 65, 79);
/// Selected-item highlight fill.
pub(crate) const SELECTION: Color32 = Color32::from_rgb(29, 81, 72);

/// Body text size in points.
const TEXT_BODY: f32 = 15.0;
/// Button label size in points.
const TEXT_BUTTON: f32 = 15.0;
/// Heading size in points.
const TEXT_HEADING: f32 = 27.0;
/// Small/caption size in points.
const TEXT_SMALL: f32 = 12.0;
/// Monospace size in points.
const TEXT_MONO: f32 = 14.0;

/// Default spacing between widgets (x, y) in points.
const ITEM_SPACING: (f32, f32) = (12.0, 12.0);
/// Inner padding of buttons (x, y) in points.
const BUTTON_PADDING: (f32, f32) = (14.0, 9.0);

/// Install the design tokens into the context's dark style.
///
/// Inputs: `ctx` — egui context to configure. Output: none; the dark theme's
/// style is replaced by the token-built style.
pub(crate) fn apply(ctx: &egui::Context) {
    ctx.set_theme(egui::Theme::Dark);
    let mut style = (*ctx.style_of(egui::Theme::Dark)).clone();
    style.visuals = egui::Visuals::dark();
    style.visuals.override_text_color = Some(TEXT);
    style.visuals.widgets.inactive.weak_bg_fill = WIDGET_INACTIVE;
    style.visuals.widgets.hovered.weak_bg_fill = WIDGET_HOVER;
    style.visuals.panel_fill = BG;
    style.visuals.window_fill = PANEL;
    style.visuals.extreme_bg_color = BG;
    style.visuals.faint_bg_color = PANEL;
    style.visuals.selection.bg_fill = SELECTION;
    style.visuals.selection.stroke = egui::Stroke::new(1.0_f32, MINT);
    style.visuals.widgets.noninteractive.bg_stroke = egui::Stroke::new(1.0_f32, LINE);
    style.visuals.widgets.inactive.bg_fill = WIDGET_INACTIVE;
    style.visuals.widgets.hovered.bg_fill = WIDGET_HOVER;
    style.spacing.item_spacing = Vec2::new(ITEM_SPACING.0, ITEM_SPACING.1);
    style.spacing.button_padding = Vec2::new(BUTTON_PADDING.0, BUTTON_PADDING.1);
    style
        .text_styles
        .insert(TextStyle::Body, FontId::proportional(TEXT_BODY));
    style
        .text_styles
        .insert(TextStyle::Button, FontId::proportional(TEXT_BUTTON));
    style
        .text_styles
        .insert(TextStyle::Heading, FontId::proportional(TEXT_HEADING));
    style
        .text_styles
        .insert(TextStyle::Small, FontId::proportional(TEXT_SMALL));
    style
        .text_styles
        .insert(TextStyle::Monospace, FontId::monospace(TEXT_MONO));
    ctx.set_style_of(egui::Theme::Dark, style);
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Relative luminance of a colour (WCAG definition).
    ///
    /// Inputs: `color` — sRGB colour. Output: luminance in `[0, 1]`.
    fn relative_luminance(color: Color32) -> f64 {
        let channel = |c: u8| {
            let s = f64::from(c) / 255.0;
            if s <= 0.039_28 {
                s / 12.92
            } else {
                ((s + 0.055) / 1.055).powf(2.4)
            }
        };
        0.2126 * channel(color.r()) + 0.7152 * channel(color.g()) + 0.0722 * channel(color.b())
    }

    /// Contrast ratio between two colours (WCAG definition).
    ///
    /// Inputs: `a`, `b` — sRGB colours. Output: ratio in `[1, 21]`.
    fn contrast_ratio(a: Color32, b: Color32) -> f64 {
        let (la, lb) = (relative_luminance(a), relative_luminance(b));
        let (hi, lo) = if la > lb { (la, lb) } else { (lb, la) };
        (hi + 0.05) / (lo + 0.05)
    }

    /// Why: readability is a product requirement — a palette tweak that drops
    /// body text below the WCAG AA 4.5:1 floor must fail the suite.
    #[test]
    fn text_colors_meet_wcag_contrast_on_their_surfaces() {
        assert!(
            contrast_ratio(TEXT, BG) >= 4.5,
            "body text on background below WCAG AA"
        );
        assert!(
            contrast_ratio(TEXT, PANEL) >= 4.5,
            "body text on panel below WCAG AA"
        );
        assert!(
            contrast_ratio(MINT, BG) >= 4.5,
            "accent text on background below WCAG AA"
        );
        assert!(
            contrast_ratio(AMBER, PANEL) >= 4.5,
            "caution text on panel below WCAG AA"
        );
        assert!(
            contrast_ratio(MUTED, BG) >= 3.0,
            "muted text below the WCAG AA large-text floor"
        );
    }

    /// Why: a mixed-up type scale silently breaks hierarchy; headings must
    /// stay larger than body text, body larger than captions.
    #[test]
    fn type_scale_keeps_visual_hierarchy() {
        assert!(TEXT_HEADING > TEXT_BODY, "headings above body");
        assert!(TEXT_BODY > TEXT_SMALL, "body above captions");
        assert!(TEXT_MONO > TEXT_SMALL, "monospace above captions");
    }
}
