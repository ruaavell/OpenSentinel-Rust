//! The content screens. Each screen owns its own small state; engine access
//! (config, quarantine listing, signature counts) is lazy so the render loop
//! stays cheap.

use super::theme::Palette;
use crate::{Config, HeuristicSensitivity};
use egui::RichText;

// =============================================================== Scan ===

pub(crate) struct ScanScreen {
    pub target: String,
    pub stop: bool,
    pub files_done: u64,
    pub last_finished: Option<LastScan>,
}

#[derive(Clone, Copy, Default)]
pub struct LastScan {
    pub cancelled: bool,
    pub elapsed_ms: u64,
    pub scanned: u64,
    pub detected: u64,
    pub suspicious: u64,
}

impl ScanScreen {
    pub(crate) fn render_ui(
        &mut self,
        ui: &mut egui::Ui,
        busy: bool,
    ) -> Option<super::app::Action> {
        card_section(ui, "Scan target");
        ui.horizontal(|ui| {
            ui.label("Path");
            ui.add(egui::TextEdit::singleline(&mut self.target).desired_width(420.0));
            if !busy {
                if ui
                    .add(green_button(RichText::new("Start scan").strong()))
                    .clicked()
                {
                    return Some(super::app::Action::StartScan(vec![self.target.clone()]));
                }
            } else {
                if self.stop {
                    ui.colored_label(Palette::TEXT2, "Stopping…");
                } else if ui.add(egui::Button::new("Stop")).clicked() {
                    self.stop = true;
                }
            }
            None
        });
        ui.add_space(8.0);

        card_section(ui, "Progress");
        if busy {
            // No total is known up front: an honest counter, not a fake
            // percentage.
            ui.horizontal(|ui| {
                ui.colored_label(
                    Palette::DARK,
                    format!("{} file(s) processed", self.files_done),
                );
                ui.colored_label(Palette::TEXT2, "counter — total unknown up front");
            });
        } else if let Some(last) = &self.last_finished {
            ui.horizontal(|ui| {
                if last.cancelled {
                    ui.colored_label(Palette::WARN, "Stopped by user");
                } else if last.detected > 0 {
                    ui.colored_label(Palette::DANGER, "Threats detected");
                } else {
                    ui.colored_label(Palette::DEEP, "Scan complete");
                }
                ui.label(format!(
                    "{} scanned · {} detected · {} suspicious · {} s",
                    last.scanned,
                    last.detected,
                    last.suspicious,
                    last.elapsed_ms / 1000
                ));
            });
        } else {
            ui.colored_label(Palette::TEXT2, "No scan has been run in this session.");
        }
        ui.add_space(8.0);
        None
    }

    pub(crate) fn reset_for_new_scan(&mut self) {
        self.files_done = 0;
        self.stop = false;
    }

    pub(crate) fn request_stop(&mut self) {
        self.stop = true;
    }

    pub(crate) fn on_tick(&mut self, files_done: u64) {
        self.files_done = files_done;
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn on_done(
        &mut self,
        scanned: u64,
        detected: u64,
        suspicious: u64,
        _errors: u64,
        _skipped: u64,
        elapsed_ms: u64,
        cancelled: bool,
    ) {
        self.last_finished = Some(LastScan {
            cancelled,
            elapsed_ms,
            scanned,
            detected,
            suspicious,
        });
    }
}

// ======================================================== Quarantine ===

#[derive(Default)]
pub(crate) struct QuarantineScreen {
    entries: Vec<crate::QuarantineEntry>,
    confirm_purge: Option<usize>,
}

impl QuarantineScreen {
    pub(crate) fn render(&mut self, ui: &mut egui::Ui) -> Option<super::app::Action> {
        self.entries = crate::list_quarantined().unwrap_or_default();
        let mut restore_id: Option<String> = None;
        let mut purge_idx: Option<usize> = None;
        card_section(ui, "Quarantined items");
        if self.entries.is_empty() {
            ui.colored_label(
                Palette::TEXT2,
                "No quarantined items. Scans never quarantine automatically — quarantine by hand from the Scan screen.",
            );
        } else {
            let root = self.root();
            egui::ScrollArea::vertical()
                .max_height(300.0)
                .show(ui, |ui| {
                    for (i, e) in self.entries.iter().enumerate() {
                        let id = e.id.clone();
                        let path_str = e.original_path.to_string_lossy().to_string();
                        let hash_short = e.sha256[..e.sha256.len().min(12)].to_string();
                        let quarantined_at = e.quarantined_at.clone();
                        card_frame(ui, |ui| {
                            ui.strong(&path_str);
                            ui.horizontal(|ui| {
                                ui.colored_label(
                                    Palette::TEXT2,
                                    format!(
                                        "sha256 {}  ·  quarantined {}",
                                        hash_short, quarantined_at
                                    ),
                                );
                            });
                            ui.horizontal(|ui| {
                                if ui.button("Restore").clicked() {
                                    restore_id = Some(id.clone());
                                }
                                if ui.button("Purge…").clicked() {
                                    purge_idx = Some(i);
                                }
                            });
                        });
                        ui.add_space(6.0);
                    }
                });
            if let Some(id) = restore_id {
                match crate::quarantine_restore(&id, &root) {
                    Ok(dst) => {
                        let _ = ui.colored_label(
                            Palette::DEEP,
                            format!("restored to {}", dst.to_string_lossy()),
                        );
                    }
                    Err(err) => {
                        let _ = ui.colored_label(Palette::WARN, err.to_string());
                    }
                }
            }
            if let Some(i) = purge_idx {
                self.confirm_purge = Some(i);
            }
            if let Some(i) = self.confirm_purge.take() {
                let entry = self.entries.get(i).cloned();
                if let Some(e) = entry {
                    let root2 = self.root();
                    egui::Window::new("Permanently delete quarantined item?")
                        .collapsible(false)
                        .resizable(false)
                        .show(ui.ctx(), |ui| {
                            ui.label("This removes the quarantined file and its record. There is no undo.");
                            ui.horizontal(|ui| {
                                if ui.button("Cancel").clicked() {
                                    ui.close();
                                }
                                if ui
                                    .add(danger_button(RichText::new("Delete").strong()))
                                    .clicked()
                                {
                                    let _ = crate::quarantine_purge(&[e.id], &root2);
                                    ui.close();
                                }
                            });
                        });
                }
            }
        }
        None
    }

    fn root(&self) -> std::path::PathBuf {
        crate::Config::load_default()
            .map(|c| c.quarantine_dir)
            .unwrap_or_default()
    }
}

// ======================================================== Database ===

#[derive(Default)]
pub(crate) struct DatabaseScreen {
    reloaded_at: Option<std::time::Instant>,
}

impl DatabaseScreen {
    pub(crate) fn render(&mut self, ui: &mut egui::Ui) {
        card_section(ui, "Threat database");
        let cfg = crate::Config::load_default().unwrap_or_default();
        let sigs = crate::load_signatures(&cfg.signatures_path);
        ui.strong(format!("Signatures loaded: {}", sigs.len()));
        ui.colored_label(
            Palette::TEXT2,
            format!("file: {}", cfg.signatures_path.to_string_lossy()),
        );
        let integrity = match std::fs::metadata(&cfg.signatures_path) {
            Ok(m) => format!("present, {} bytes", m.len()),
            Err(_) => "missing".to_string(),
        };
        ui.colored_label(Palette::TEXT2, format!("Integrity: {integrity}"));
        ui.colored_label(
            Palette::WARN,
            "Update source not configured — no online feed is wired in; the local DB is used as-is.",
        );
        if ui.button("Reload signatures").clicked() {
            self.reloaded_at = Some(std::time::Instant::now());
        }
        if let Some(t) = self.reloaded_at {
            ui.colored_label(
                Palette::DEEP,
                format!(
                    "reloaded {} s ago ({} signatures)",
                    t.elapsed().as_secs_f64().round(),
                    sigs.len()
                ),
            );
        }
    }
}

// ======================================================== Activity ===

pub(crate) struct ActivityLine {
    pub when: std::time::SystemTime,
    pub text: String,
    pub danger: bool,
}

#[derive(Default)]
pub(crate) struct ActivityScreen {
    log: Vec<ActivityLine>,
}

impl ActivityScreen {
    pub(crate) fn render(&mut self, ui: &mut egui::Ui) {
        card_section(ui, "Activity");
        if self.log.is_empty() {
            ui.colored_label(
                Palette::TEXT2,
                "Nothing recorded yet this session. History is in-memory only and does not survive a restart.",
            );
        } else {
            egui::ScrollArea::vertical()
                .max_height(300.0)
                .show(ui, |ui| {
                    for line in self.log.iter().rev() {
                        let color = if line.danger {
                            Palette::DANGER
                        } else {
                            Palette::TEXT2
                        };
                        let secs = line
                            .when
                            .duration_since(std::time::UNIX_EPOCH)
                            .map(|d| d.as_secs())
                            .unwrap_or(0);
                        ui.horizontal(|ui| {
                            ui.colored_label(color, format!("[{secs:010}]"));
                            ui.colored_label(Palette::TEXT, &line.text);
                        });
                    }
                });
        }
    }

    pub(crate) fn push(&mut self, text: String, danger: bool) {
        self.log.push(ActivityLine {
            when: std::time::SystemTime::now(),
            text,
            danger,
        });
        if self.log.len() > 200 {
            self.log.drain(0..self.log.len() - 200);
        }
    }
}

// ======================================================== Settings ===

pub(crate) struct SettingsScreen {
    editing: Config,
    sensitivity_idx: usize,
    sig_path: String,
    quar_dir: String,
    saved_at: Option<std::time::Instant>,
}

impl Default for SettingsScreen {
    fn default() -> Self {
        let c = Config::load_default().unwrap_or_default();
        let idx = match c.heuristic_sensitivity {
            HeuristicSensitivity::Low => 0,
            HeuristicSensitivity::Medium => 1,
            HeuristicSensitivity::High => 2,
        };
        Self {
            editing: c,
            sensitivity_idx: idx,
            sig_path: String::new(),
            quar_dir: String::new(),
            saved_at: None,
        }
    }
}

impl SettingsScreen {
    pub(crate) fn render(&mut self, ui: &mut egui::Ui) {
        self.sig_path = self.editing.signatures_path.to_string_lossy().to_string();
        self.quar_dir = self.editing.quarantine_dir.to_string_lossy().to_string();

        card_section(ui, "Scanning");
        ui.horizontal(|ui| {
            ui.label("Concurrency (1–64)");
            ui.add(egui::Slider::new(&mut self.editing.concurrency, 1..=64).text(""));
        });
        ui.horizontal(|ui| {
            ui.label("Max file size (bytes)");
            ui.add(egui::DragValue::new(&mut self.editing.max_file_size));
        });
        ui.horizontal(|ui| {
            ui.checkbox(&mut self.editing.heuristics, "Heuristics");
            ui.label("Sensitivity");
            let names = ["Low", "Medium", "High"];
            egui::ComboBox::from_label("sensitivity")
                .selected_text(names[self.sensitivity_idx])
                .show_ui(ui, |ui| {
                    for (i, name) in names.iter().enumerate() {
                        let clicked = ui
                            .selectable_label(i == self.sensitivity_idx, *name)
                            .clicked();
                        if clicked {
                            self.sensitivity_idx = i;
                        }
                    }
                });
        });

        ui.add_space(10.0);
        card_section(ui, "Storage");
        ui.horizontal(|ui| {
            ui.label("Signatures path");
            ui.add(egui::TextEdit::singleline(&mut self.sig_path).desired_width(320.0));
        });
        ui.horizontal(|ui| {
            ui.label("Quarantine dir");
            ui.add(egui::TextEdit::singleline(&mut self.quar_dir).desired_width(320.0));
        });

        ui.add_space(10.0);
        if ui
            .add(green_button(RichText::new("Save settings").strong()))
            .clicked()
        {
            match self.save() {
                Ok(()) => self.saved_at = Some(std::time::Instant::now()),
                Err(e) => {
                    ui.colored_label(Palette::DANGER, e.to_string());
                }
            }
        }
        if let Some(t) = self.saved_at {
            ui.colored_label(
                Palette::DEEP,
                format!("saved {} s ago", t.elapsed().as_secs()),
            );
        }
        ui.colored_label(
            Palette::TEXT2,
            "Local-only operation: no telemetry, no accounts, no data leaves this machine.",
        );
    }

    fn save(&mut self) -> Result<(), crate::Error> {
        self.editing.heuristic_sensitivity = match self.sensitivity_idx {
            0 => HeuristicSensitivity::Low,
            1 => HeuristicSensitivity::Medium,
            _ => HeuristicSensitivity::High,
        };
        self.editing.signatures_path = std::path::PathBuf::from(&self.sig_path);
        self.editing.quarantine_dir = std::path::PathBuf::from(&self.quar_dir);
        let dir = std::env::current_dir().map_err(|e| {
            crate::Error::new(crate::ErrorKind::Config, format!("cannot find cwd: {e}"))
        })?;
        let path = dir.join("opensentinel.toml");
        std::fs::write(&path, self.editing.to_toml()).map_err(|e| {
            crate::Error::new(
                crate::ErrorKind::Config,
                format!("cannot write {}: {e}", path.display()),
            )
        })?;
        self.editing = Config::load_default()?;
        Ok(())
    }
}

// ==================================================== all screens host ===

pub(crate) struct Screens {
    pub scan: ScanScreen,
    pub quarantine: QuarantineScreen,
    pub database: DatabaseScreen,
    pub activity: ActivityScreen,
    pub settings: SettingsScreen,
}

impl Default for Screens {
    fn default() -> Self {
        Self {
            scan: ScanScreen {
                target: default_scan_target(),
                stop: false,
                files_done: 0,
                last_finished: None,
            },
            quarantine: QuarantineScreen::default(),
            database: DatabaseScreen::default(),
            activity: ActivityScreen::default(),
            settings: SettingsScreen::default(),
        }
    }
}

impl Screens {
    /// Render the active screen. Returns a pending `Action` for the `App` to
    /// execute after the frame, so the screens never borrow `App` back.
    pub(crate) fn render(
        &mut self,
        ui: &mut egui::Ui,
        screen: Screen,
        busy: bool,
    ) -> Option<super::app::Action> {
        ui.add_space(12.0);
        let action = match screen {
            Screen::Overview => self.overview(ui, busy),
            Screen::Scan => self.scan.render_ui(ui, busy),
            Screen::Quarantine => {
                self.quarantine.render(ui);
                None
            }
            Screen::Database => {
                self.database.render(ui);
                None
            }
            Screen::Activity => {
                self.activity.render(ui);
                None
            }
            Screen::Settings => {
                self.settings.render(ui);
                None
            }
        };
        ui.add_space(12.0);
        action
    }

    fn overview(&mut self, ui: &mut egui::Ui, busy: bool) -> Option<super::app::Action> {
        let hour = local_hour();
        let greeting = if (6..12).contains(&hour) {
            "Good morning"
        } else if (12..18).contains(&hour) {
            "Good afternoon"
        } else if (18..24).contains(&hour) {
            "Good evening"
        } else {
            "Hello"
        };
        egui::Frame::NONE
            .fill(Palette::PALE)
            .corner_radius(egui::CornerRadius::same(10))
            .inner_margin(12.0)
            .show(ui, |ui| {
                ui.horizontal(|ui| {
                    ui.strong(greeting.to_string());
                    ui.colored_label(Palette::TEXT2, "— security overview");
                });
                let sigs = {
                    let cfg = Config::load_default().unwrap_or_default();
                    crate::load_signatures(&cfg.signatures_path)
                };
                ui.horizontal(|ui| {
                    ui.colored_label(Palette::DEEP, "●");
                    ui.label(if busy {
                        "Scanner ready — scan in progress".to_string()
                    } else if sigs.is_empty() {
                        "Scanner ready — signature DB empty".to_string()
                    } else {
                        "Scanner ready".to_string()
                    });
                });
                if let Some(last) = &self.scan.last_finished {
                    ui.colored_label(
                        Palette::TEXT2,
                        format!(
                            "Last scan {} — {} s",
                            if last.cancelled {
                                "stopped by user"
                            } else {
                                "finished"
                            },
                            last.elapsed_ms / 1000
                        ),
                    );
                }
            });
        ui.add_space(8.0);

        card_section(ui, "Quick actions");
        let mut action: Option<super::app::Action> = None;
        ui.horizontal(|ui| {
            if ui
                .add(green_button(RichText::new("Scan current folder").strong()))
                .clicked()
            {
                action = Some(super::app::Action::StartScan(vec![default_scan_target()]));
            }
            if ui.button("View quarantine").clicked() {
                action = Some(super::app::Action::GoTo(Screen::Quarantine));
            }
            if ui.button("Update DB").clicked() {
                action = Some(super::app::Action::GoTo(Screen::Database));
            }
        });
        ui.add_space(8.0);

        card_section(ui, "Last scan");
        match &self.scan.last_finished {
            Some(last) => {
                ui.horizontal(|ui| {
                    if last.detected > 0 {
                        ui.colored_label(
                            Palette::DANGER,
                            format!("{} threats detected", last.detected),
                        );
                    } else {
                        ui.colored_label(Palette::DEEP, "No threats detected");
                    }
                    ui.label(format!(
                        "{} scanned · {} suspicious · {} s",
                        last.scanned,
                        last.suspicious,
                        last.elapsed_ms / 1000
                    ));
                });
            }
            None => {
                ui.colored_label(Palette::TEXT2, "No scan has been run in this session.");
            }
        }
        action
    }
}

fn default_scan_target() -> String {
    std::env::current_dir()
        .map(|p| p.to_string_lossy().to_string())
        .unwrap_or_else(|_| ".".to_string())
}

fn local_hour() -> u8 {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    ((secs % 86_400) / 3600) as u8
}

// ------------------------------------------------------------ widgets ===

#[derive(Clone, Copy)]
pub(crate) enum Screen {
    Overview,
    Scan,
    Quarantine,
    Database,
    Activity,
    Settings,
}

impl PartialEq for Screen {
    fn eq(&self, other: &Self) -> bool {
        std::mem::discriminant(self) == std::mem::discriminant(other)
    }
}

pub(crate) fn card_section(ui: &mut egui::Ui, title: &str) {
    egui::Frame::NONE
        .fill(Palette::WHITE)
        .corner_radius(egui::CornerRadius::same(10))
        .stroke(egui::Stroke::new(1.0, Palette::BORDER))
        .inner_margin(12.0)
        .show(ui, |ui| {
            ui.strong(title);
            ui.add_space(6.0);
        });
}

pub(crate) fn card_frame(ui: &mut egui::Ui, f: impl FnOnce(&mut egui::Ui)) {
    egui::Frame::NONE
        .fill(Palette::WHITE)
        .corner_radius(egui::CornerRadius::same(8))
        .stroke(egui::Stroke::new(1.0, Palette::BORDER))
        .inner_margin(10.0)
        .show(ui, f);
}

pub(crate) fn green_button(text: impl Into<egui::WidgetText>) -> egui::Button<'static> {
    egui::Button::new(text).fill(Palette::PRIMARY)
}

pub(crate) fn danger_button(text: impl Into<egui::WidgetText>) -> egui::Button<'static> {
    egui::Button::new(text).fill(Palette::DANGER)
}
