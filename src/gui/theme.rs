//! Green-and-white design tokens, applied to the egui visual style on every
//! frame start. Kept to one place so the palette stays consistent.

use egui::{Color32, CornerRadius, Visuals};

/// The fixed palette. One source of truth; `style()` derives egui styles
/// from it.
#[derive(Clone, Copy)]
pub(crate) struct Palette;

impl Palette {
    pub const PRIMARY: Color32 = Color32::from_rgb(0x16, 0xA3, 0x4A);
    pub const DARK: Color32 = Color32::from_rgb(0x15, 0x80, 0x3D);
    pub const DEEP: Color32 = Color32::from_rgb(0x16, 0x65, 0x34);
    pub const PALE: Color32 = Color32::from_rgb(0xF0, 0xFD, 0xF4);
    pub const WHITE: Color32 = Color32::from_rgb(0xFF, 0xFF, 0xFF);
    pub const BG: Color32 = Color32::from_rgb(0xF7, 0xF9, 0xF7);
    pub const TEXT: Color32 = Color32::from_rgb(0x17, 0x21, 0x1B);
    pub const TEXT2: Color32 = Color32::from_rgb(0x68, 0x74, 0x6B);
    pub const BORDER: Color32 = Color32::from_rgb(0xE4, 0xEA, 0xE5);
    pub const WARN: Color32 = Color32::from_rgb(0xD9, 0x77, 0x06);
    pub const DANGER: Color32 = Color32::from_rgb(0xDC, 0x26, 0x26);

    /// egui style for the light theme, derived from the palette.
    pub(crate) fn style() -> egui::Style {
        let mut visuals: Visuals = Visuals::light();
        visuals.dark_mode = false;
        visuals.window_fill = Self::WHITE;
        visuals.widgets.noninteractive.weak_bg_fill = Self::BG;
        visuals.widgets.noninteractive.bg_fill = Self::WHITE;
        visuals.widgets.noninteractive.bg_stroke = egui::Stroke::new(1.0, Self::BORDER);
        visuals.widgets.inactive.weak_bg_fill = Self::PALE;
        visuals.widgets.inactive.bg_fill = Self::WHITE;
        visuals.widgets.inactive.bg_stroke = egui::Stroke::new(1.0, Self::BORDER);
        visuals.widgets.hovered.weak_bg_fill = Self::PALE;
        visuals.widgets.hovered.bg_fill = Self::WHITE;
        visuals.widgets.hovered.bg_stroke = egui::Stroke::new(1.0, Self::PRIMARY);
        visuals.widgets.active.weak_bg_fill = Color32::from_rgb(0xD1, 0xFA, 0xE5);
        visuals.widgets.active.bg_fill = Self::WHITE;
        visuals.widgets.active.bg_stroke = egui::Stroke::new(1.0, Self::DARK);
        visuals.window_corner_radius = CornerRadius::same(10);
        visuals.menu_corner_radius = CornerRadius::same(8);
        for w in [
            &mut visuals.widgets.noninteractive,
            &mut visuals.widgets.inactive,
            &mut visuals.widgets.hovered,
            &mut visuals.widgets.active,
        ] {
            w.corner_radius = CornerRadius::same(6);
        }
        egui::Style {
            visuals,
            ..egui::Style::default()
        }
    }
}
