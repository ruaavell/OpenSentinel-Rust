//! OpenSentinel desktop GUI binary.
//!
//! Thin eframe launcher. All UI state, screens and engine integration live in
//! the `opensentinel::gui` module of the library so they are testable without
//! a display.

fn main() -> eframe::Result {
    eframe::run_native(
        "OpenSentinel",
        eframe::NativeOptions {
            viewport: egui::ViewportBuilder::default()
                .with_inner_size([1080.0, 700.0])
                .with_min_inner_size([800.0, 560.0]),
            ..Default::default()
        },
        Box::new(|_cc| {
            let app = opensentinel::gui::App::new();
            Ok(Box::new(app))
        }),
    )
}
