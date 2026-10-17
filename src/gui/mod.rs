//! Desktop GUI for OpenSentinel, built with egui/eframe.
//!
//! Layout: a compact left sidebar (navigation + branding) and a content area
//! that swaps screens. All engine work happens on a background thread; the
//! UI thread only renders and dispatches commands, so scanning never blocks
//! the window.

mod app;
mod screens;
mod theme;

pub use app::App;
pub use screens::LastScan;
