//! Top-level application state: owns UI layout, navigation, and the
//! background task channel that decouples the egui render loop from the
//! engine's actual work.

use super::screens::{Screen, Screens};
use super::theme::Palette;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::Arc;

/// Action emitted by a screen during `render`; decoded by `App` after the
/// frame so the screen never borrows back into `App`.
pub(crate) enum Action {
    StartScan(Vec<String>),
    GoTo(super::screens::Screen),
}

/// Messages from the background scan worker to the UI thread.
pub(crate) enum WorkerMsg {
    /// Progress tick: files processed so far. The scanner can't report a
    /// total up front, so progress is a real counter, not a fake percentage.
    Tick { files_done: u64 },
    /// The scan ended (naturally or cancelled) with final counts.
    Done {
        scanned: u64,
        detected: u64,
        suspicious: u64,
        errors: u64,
        skipped: u64,
        elapsed_ms: u64,
        cancelled: bool,
    },
}

/// The eframe app root. Implements `eframe::App`.
pub struct App {
    pub(crate) screen: Screen,
    pub(crate) screens: Screens,
    pub(crate) cfg: crate::Config,
    worker_rx: Option<Receiver<WorkerMsg>>,
    stop_flag: Arc<AtomicBool>,
    pub(crate) busy: bool,
}

impl Default for App {
    fn default() -> Self {
        Self::new()
    }
}

impl App {
    pub fn new() -> Self {
        Self {
            screen: Screen::Overview,
            screens: Screens::default(),
            cfg: crate::Config::load_default().unwrap_or_default(),
            worker_rx: None,
            stop_flag: Arc::new(AtomicBool::new(false)),
            busy: false,
        }
    }

    /// Start a background scan of `paths`. The receiver is stored and
    /// drained every frame so the UI stays responsive; `busy` blocks a
    /// second overlapping scan until the first finishes.
    pub fn start_scan(&mut self, paths: Vec<String>) {
        if self.busy || paths.is_empty() {
            return;
        }
        let rx = spawn_scan(&paths, &self.cfg, self.stop_flag.clone());
        self.worker_rx = Some(rx);
        self.stop_flag.store(false, Ordering::Relaxed);
        self.busy = true;
        self.screens.scan.reset_for_new_scan();
    }

    /// Ask the running scan to stop at the next safe point. The scanner
    /// checks this flag between files; in-flight work is never aborted.
    pub fn request_stop(&mut self) {
        if self.busy {
            self.stop_flag.store(true, Ordering::Relaxed);
            self.screens.scan.request_stop();
        }
    }

    fn drain_worker(&mut self, ctx: &egui::Context) {
        // Swap out the receiver so the borrow ends before we mutate.
        let Some(rx) = self.worker_rx.take() else {
            return;
        };
        let mut done: Option<WorkerMsg> = None;
        let mut got = false;
        while let Ok(msg) = rx.try_recv() {
            got = true;
            match msg {
                WorkerMsg::Tick { files_done } => {
                    self.screens.scan.on_tick(files_done);
                }
                WorkerMsg::Done { .. } => {
                    done = Some(msg);
                }
            }
        }
        if let Some(msg) = done {
            match msg {
                WorkerMsg::Done {
                    scanned,
                    detected,
                    suspicious,
                    errors,
                    skipped,
                    elapsed_ms,
                    cancelled,
                } => {
                    self.screens.scan.on_done(
                        scanned, detected, suspicious, errors, skipped, elapsed_ms, cancelled,
                    );
                    self.screens.activity.push(
                        if cancelled {
                            format!(
                                "Scan stopped — {scanned} files in {} s",
                                elapsed_ms / 1000
                            )
                        } else {
                            format!(
                                "Scan finished — {scanned} scanned, {detected} detected, {suspicious} suspicious, {} s",
                                elapsed_ms / 1000
                            )
                        },
                        detected > 0,
                    );
                }
                WorkerMsg::Tick { .. } => {}
            }
        } else {
            self.worker_rx = Some(rx);
        }
        if got {
            ctx.request_repaint();
        }
    }
}

impl eframe::App for App {
    fn ui(&mut self, ui: &mut egui::Ui, frame: &mut eframe::Frame) {
        let ctx = ui.ctx().clone();
        ctx.set_style_of(egui::Theme::Light, Palette::style());

        // Top bar.
        egui::Panel::top("topbar")
            .frame(egui::Frame::NONE)
            .show(ui, |ui| {
                ui.add_space(4.0);
                ui.horizontal(|ui| {
                    ui.strong("OpenSentinel");
                    ui.label("· lightweight open-source antivirus");
                });
                ui.add_space(4.0);
            });

        // Sidebar.
        egui::Panel::left("sidebar")
            .frame(egui::Frame::NONE)
            .resizable(false)
            .exact_size(200.0)
            .show(ui, |ui| self.render_sidebar(ui));

        // Content.
        egui::Frame::central_panel(&ctx.style_of(egui::Theme::Light)).show(ui, |ui| {
            self.drain_worker(&ctx);
            if let Some(action) = self.screens.render(ui, self.screen, self.busy) {
                match action {
                    Action::StartScan(paths) => self.start_scan(paths),
                    Action::GoTo(s) => self.screen = s,
                }
            }
            if self.screens.scan.stop {
                self.request_stop();
            }
        });

        // egui repaints on events by default; poll the worker while a scan
        // runs so the progress counter keeps moving without a timer.
        if self.busy {
            ctx.request_repaint_after(std::time::Duration::from_millis(100));
        }
        let _ = frame;
    }
}

impl App {
    fn render_sidebar(&mut self, ui: &mut egui::Ui) {
        egui::Frame::NONE
            .fill(Palette::WHITE)
            .corner_radius(egui::CornerRadius::same(10))
            .stroke(egui::Stroke::new(1.0, Palette::BORDER))
            .show(ui, |ui| {
                ui.vertical_centered_justified(|ui| {
                    ui.strong("OpenSentinel");
                    ui.colored_label(Palette::TEXT2, "Antivirus");
                });
                ui.add_space(10.0);
            });

        ui.separator();
        ui.add_space(6.0);

        let items: &[(Screen, &str)] = &[
            (Screen::Overview, "Overview"),
            (Screen::Scan, "Scan"),
            (Screen::Quarantine, "Quarantine"),
            (Screen::Database, "Threat database"),
            (Screen::Activity, "Activity"),
            (Screen::Settings, "Settings"),
        ];
        for (scr, label) in items {
            let target = *scr;
            let active = self.screen == target;
            egui::Frame::NONE
                .fill(if active {
                    Palette::PALE
                } else {
                    Palette::WHITE
                })
                .corner_radius(egui::CornerRadius::same(8))
                .stroke(if active {
                    egui::Stroke::new(1.0, Palette::PRIMARY)
                } else {
                    egui::Stroke::NONE
                })
                .show(ui, |ui| {
                    let mut text = egui::RichText::new(*label);
                    if active {
                        text = text.strong();
                    }
                    text = text.color(if active { Palette::DARK } else { Palette::TEXT });
                    let _ = ui.selectable_label(active, text);
                });
            if active {
                self.screen = target;
            }
        }

        ui.with_layout(egui::Layout::bottom_up(egui::Align::Min), |ui| {
            ui.add_space(6.0);
            ui.colored_label(Palette::TEXT2, format!("v{}", env!("CARGO_PKG_VERSION")));
            ui.add_space(6.0);
        });
    }
}

/// Spawn the background worker. The stop flag is shared with the UI so the
/// Stop button takes effect between files.
fn spawn_scan(paths: &[String], cfg: &crate::Config, stop: Arc<AtomicBool>) -> Receiver<WorkerMsg> {
    let (tx, rx) = mpsc::channel();
    let cfg = cfg.clone();
    let paths = paths.to_vec();
    std::thread::spawn(move || {
        run_scan_worker(&cfg, &tx, &paths, stop);
    });
    rx
}

fn run_scan_worker(
    cfg: &crate::Config,
    tx: &Sender<WorkerMsg>,
    paths: &[String],
    stop: Arc<AtomicBool>,
) {
    use crate::{build_engine, scan_paths_full, summary_counts};

    let engine = match build_engine(cfg) {
        Ok(e) => e,
        Err(e) => {
            eprintln!("OpenSentinel: {e}");
            let _ = tx.send(WorkerMsg::Done {
                scanned: 0,
                detected: 0,
                suspicious: 0,
                errors: 0,
                skipped: 0,
                elapsed_ms: 0,
                cancelled: false,
            });
            return;
        }
    };

    // Forward at most one Tick per 8 progress events so a large tree never
    // drowns the UI thread. The counter is the source of truth.
    let (ptx, prx) = mpsc::channel();
    let forward: Sender<WorkerMsg> = tx.clone();
    let coalesce = std::thread::spawn(move || {
        let mut n = 0u64;
        while let Ok(_ev) = prx.recv() {
            n += 1;
            if n.is_multiple_of(8) {
                let _ = forward.send(WorkerMsg::Tick { files_done: n });
            }
        }
    });

    let t0 = std::time::Instant::now();
    let mut results: Vec<crate::FileResult> = Vec::new();
    let res = scan_paths_full(paths, cfg, &engine, &mut results, Some(&ptx), &stop);
    let cancelled = matches!(res, Err(ref e) if e.kind == crate::ErrorKind::Cancelled);
    let elapsed_ms = t0.elapsed().as_millis() as u64;

    // Close the progress sender so the coalescer thread exits; then wait.
    drop(ptx);
    let _ = coalesce.join();

    let counts = summary_counts(&results);
    let _ = tx.send(WorkerMsg::Done {
        scanned: counts.clean as u64,
        detected: counts.detected as u64,
        suspicious: counts.suspicious as u64,
        errors: counts.errors as u64,
        skipped: counts.skipped as u64,
        elapsed_ms,
        cancelled,
    });
}
