//! egui GUI: load an EPROM dump, run the Auto-Fix search on a background
//! thread while showing progress, adjust the address/data bit mapping
//! manually if needed, and save the result.

use std::collections::VecDeque;
use std::path::PathBuf;
use std::sync::mpsc::{Receiver, TryRecvError};
use std::thread;
use std::time::Duration;

use dec_rom::autofix::{find_scrambling, AutoFixResult, Confidence};
use dec_rom::reorganizer::{apply_data_lut, build_data_lut, AddrDiff, Rom};
use dec_rom::scheme_txt::{parse_scheme_txt, write_scheme_txt};

/// Default shown in the budget dropdown on startup.
const DEFAULT_TIME_BUDGET_MINUTES: u32 = 1;

/// Selectable range for the budget dropdown, in whole minutes.
const TIME_BUDGET_MINUTES_RANGE: std::ops::RangeInclusive<u32> = 1..=5;

/// Cap on the read-only log panel's line count - oldest lines are dropped
/// first, so a long session can't grow it unbounded.
const LOG_MAX_LINES: usize = 200;

const IDENTITY_DATA_MAP: [u32; 8] = [0, 1, 2, 3, 4, 5, 6, 7];

/// Interface language. Only covers this file's own static labels - error
/// strings from `reorganizer`/`scheme_txt` and Auto-Fix's own progress
/// messages (`autofix::find_scrambling`) are generated deep in the engine
/// and already English-only regardless of this toggle, same as before it
/// existed.
#[derive(Clone, Copy, PartialEq)]
enum Lang {
    Pt,
    En,
}

/// Picks `pt` or `en` depending on `lang` - the interface's whole
/// translation mechanism, deliberately this simple since `src/ui.rs` is
/// the only place with user-facing strings to translate.
fn t(lang: Lang, pt: &'static str, en: &'static str) -> &'static str {
    match lang {
        Lang::Pt => pt,
        Lang::En => en,
    }
}

enum SearchMessage {
    Progress(u32, String),
    Done(AutoFixResult),
}

struct LoadedRom {
    path: PathBuf,
    rom: Rom,
}

/// An action collected while rendering (read-only borrows of `self.result`
/// are still live at that point) and applied afterward, once those borrows
/// have ended — avoids borrowing `self` both immutably (to read the current
/// result/candidate) and mutably (to act on a click) at the same time.
enum Action {
    Load,
    StartAutofix,
    Save,
    LoadScheme,
    SaveScheme,
}

pub struct DecRomApp {
    loaded: Option<LoadedRom>,
    error: Option<String>,
    search: Option<Receiver<SearchMessage>>,
    progress: (u32, String),
    result: Option<AutoFixResult>,
    selected_candidate: usize,
    time_budget_minutes: u32,
    /// The address/data bit mapping currently in effect - what `Save` writes
    /// and what the hex view (see `hex_view`) displays. Auto-populated from
    /// an Auto-Fix result (the winner for `High`, or whichever candidate is
    /// selected for `Marginal`) whenever one becomes available, but also
    /// directly editable by hand (see the left panel's address/data bit
    /// dropdowns) - manual edits after that point stick until the next
    /// Auto-Fix run or candidate selection overwrites them again.
    manual_addr_map: Vec<u32>,
    manual_data_map: [u32; 8],
    /// Recomputed from `manual_addr_map`/`manual_data_map` at the few points
    /// that can change them, rather than every frame - `AddrDiff::apply_full`
    /// is O(file size), cheap once but not worth repeating on every repaint
    /// this file's own scrollbar triggers.
    displayed_bytes: Vec<u8>,
    /// Free-text "Comentários" field for the next scheme `.txt` save (see
    /// `scheme_txt`) - the MSX community's own scheme-sharing format
    /// dedicates this field to a human-readable interface/product name, so
    /// it's left to the user rather than guessed.
    scheme_comment: String,
    /// Whether the "Sobre" dialog is currently shown.
    about_open: bool,
    lang: Lang,
    /// Read-only action history shown in the terminal-style log panel
    /// below the scheme section (see `log`) - file loads/saves, scheme
    /// loads/saves, and Auto-Fix start/finish, each with their outcome.
    /// Deliberately does *not* relay Auto-Fix's own per-candidate
    /// progress messages (`SearchMessage::Progress`) - those already have
    /// a live progress bar, and logging every one of them (potentially
    /// thousands per run) would bury the events that actually matter.
    log_lines: VecDeque<String>,
}

impl Default for DecRomApp {
    fn default() -> Self {
        Self {
            loaded: None,
            error: None,
            search: None,
            progress: (0, String::new()),
            result: None,
            selected_candidate: 0,
            time_budget_minutes: DEFAULT_TIME_BUDGET_MINUTES,
            manual_addr_map: Vec::new(),
            manual_data_map: IDENTITY_DATA_MAP,
            displayed_bytes: Vec::new(),
            scheme_comment: String::new(),
            about_open: false,
            lang: Lang::Pt,
            log_lines: VecDeque::new(),
        }
    }
}

impl DecRomApp {
    /// Appends a line to the read-only log panel.
    fn log(&mut self, msg: impl Into<String>) {
        self.log_lines.push_back(msg.into());
        if self.log_lines.len() > LOG_MAX_LINES {
            self.log_lines.pop_front();
        }
    }

    fn load_rom(&mut self) {
        // Native file-picker extension filters are case-sensitive on at
        // least the Linux/GTK backend, and real dumps in the wild are
        // routinely named with uppercase extensions (e.g. "TPX102.BIN",
        // "DDX12 cks-$650Dh.ROM") - both cases are listed explicitly so
        // those files aren't invisible in the picker, even though
        // `Rom::load`'s own extension sniff is already case-insensitive
        // (`is_hex_path`'s `eq_ignore_ascii_case`).
        let Some(path) = rfd::FileDialog::new()
            .add_filter("EPROM dump", &["bin", "rom", "hex", "BIN", "ROM", "HEX"])
            .pick_file()
        else {
            return;
        };
        match Rom::load(&path) {
            Ok(rom) => {
                let opened_msg = format!("{}: {}", t(self.lang, "Arquivo aberto", "File opened"), path.display());
                self.manual_addr_map = (0..rom.address_bits).collect();
                self.manual_data_map = IDENTITY_DATA_MAP;
                self.loaded = Some(LoadedRom { path, rom });
                self.error = None;
                self.result = None;
                self.selected_candidate = 0;
                self.refresh_displayed_bytes();
                self.log(opened_msg);
            }
            Err(e) => {
                self.log(format!("{}: {}", t(self.lang, "Erro ao carregar arquivo", "Error loading file"), e));
                self.error = Some(e);
            }
        }
    }

    fn descramble(&self, addr_map: &[u32], data_map: [u32; 8]) -> Vec<u8> {
        let Some(loaded) = &self.loaded else { return Vec::new() };
        let diff = AddrDiff::from_full_map(addr_map);
        let reordered = diff.apply_full(&loaded.rom.data);
        let lut = build_data_lut(&data_map);
        apply_data_lut(&reordered, &lut)
    }

    /// Recomputes `self.displayed_bytes` from `manual_addr_map`/
    /// `manual_data_map` - call after either changes.
    fn refresh_displayed_bytes(&mut self) {
        self.displayed_bytes = self.descramble(&self.manual_addr_map, self.manual_data_map);
    }

    /// Loads the manual address/data maps from the current Auto-Fix result
    /// (the winner for `High`, the selected candidate for `Marginal`) and
    /// refreshes the hex view from them - call after a search completes or
    /// the selected `Marginal` candidate changes.
    fn sync_manual_from_result(&mut self) {
        let Some(result) = &self.result else { return };
        let (addr_map, data_map) = match &result.confidence {
            Confidence::High => (result.addr_map.clone(), result.data_map),
            Confidence::Marginal(candidates) => match candidates.get(self.selected_candidate) {
                Some(c) => (c.addr_map.clone(), c.data_map),
                None => (result.addr_map.clone(), result.data_map),
            },
        };
        self.manual_addr_map = addr_map;
        self.manual_data_map = data_map;
        self.refresh_displayed_bytes();
    }

    fn start_autofix(&mut self) {
        let Some(loaded) = &self.loaded else { return };
        let data = loaded.rom.data.clone();
        let addr_bits = loaded.rom.address_bits;
        let (tx, rx) = std::sync::mpsc::channel();
        self.search = Some(rx);
        self.result = None;
        self.selected_candidate = 0;
        self.progress = (0, t(self.lang, "Iniciando...", "Starting...").to_string());
        self.log(t(self.lang, "Auto-Fix iniciado...", "Auto-Fix started...").to_string());
        let seed: u64 = rand::random();
        let time_budget = Duration::from_secs(self.time_budget_minutes as u64 * 60);
        let progress_tx = tx.clone();
        thread::spawn(move || {
            let result = find_scrambling(&data, addr_bits, time_budget, seed, move |pct, msg| {
                let _ = progress_tx.send(SearchMessage::Progress(pct, msg.to_string()));
            });
            let _ = tx.send(SearchMessage::Done(result));
        });
    }

    fn poll_search(&mut self) {
        let Some(rx) = self.search.take() else { return };
        let mut finished = false;
        let mut disconnected = false;
        loop {
            match rx.try_recv() {
                Ok(SearchMessage::Progress(pct, text)) => self.progress = (pct, text),
                Ok(SearchMessage::Done(result)) => {
                    self.result = Some(result);
                    finished = true;
                }
                Err(TryRecvError::Empty) => break,
                // The search thread exited without sending `Done` - almost
                // certainly a panic in `find_scrambling`. Surface it as a
                // normal error instead of leaving `self.search` permanently
                // `Some`, which would freeze the progress bar and keep the
                // Auto-Fix button disabled forever with no way to recover
                // short of restarting the app.
                Err(TryRecvError::Disconnected) => {
                    disconnected = true;
                    break;
                }
            }
        }
        if finished {
            self.sync_manual_from_result();
            self.log_autofix_result();
        } else if disconnected {
            let msg = t(
                self.lang,
                "Auto-Fix falhou inesperadamente (a busca terminou sem resultado)",
                "Auto-Fix failed unexpectedly (search ended without a result)",
            )
            .to_string();
            self.log(msg.clone());
            self.error = Some(msg);
        } else {
            self.search = Some(rx);
        }
    }

    /// Logs a one-line summary of the just-finished Auto-Fix result - call
    /// once `self.result` is populated.
    fn log_autofix_result(&mut self) {
        let Some(result) = &self.result else { return };
        let msg = match &result.confidence {
            Confidence::High => format!(
                "{} — {}: {}, score: {:.3}, coverage: {:.3} ({:.1}s)",
                t(self.lang, "Auto-Fix concluído (alta confiança)", "Auto-Fix finished (high confidence)"),
                t(self.lang, "processador", "processor"),
                result.processor.label(),
                result.score,
                result.coverage,
                result.elapsed.as_secs_f64()
            ),
            Confidence::Marginal(candidates) => format!(
                "{} ({} {}, {:.1}s)",
                t(self.lang, "Auto-Fix concluído (confiança marginal)", "Auto-Fix finished (marginal confidence)"),
                candidates.len(),
                t(self.lang, "candidatos", "candidates"),
                result.elapsed.as_secs_f64()
            ),
        };
        self.log(msg);
    }

    fn save_mapping(&mut self) {
        let processed = self.descramble(&self.manual_addr_map, self.manual_data_map);
        // `Rom::save` dispatches on the chosen path's own extension (the
        // same sniff `Rom::load` uses) - these filters are purely a picker
        // hint, not what decides the output format.
        let Some(path) = rfd::FileDialog::new()
            .add_filter("Binary dump", &["bin", "rom", "BIN", "ROM"])
            .add_filter("Intel HEX", &["hex", "HEX"])
            .save_file()
        else {
            return;
        };
        match Rom::save(&path, &processed) {
            Ok(()) => {
                self.error = None;
                self.log(format!("{}: {}", t(self.lang, "Arquivo salvo", "File saved"), path.display()));
            }
            Err(e) => {
                self.log(format!("{}: {}", t(self.lang, "Erro ao salvar arquivo", "Error saving file"), e));
                self.error = Some(e);
            }
        }
    }

    /// Loads an address/data bit-wiring scheme from the `.txt` format the
    /// MSX ROM-decoding community's own tooling uses (see `scheme_txt`),
    /// adapting it to the currently loaded ROM's address-bit count.
    fn load_scheme(&mut self) {
        let Some(loaded) = &self.loaded else { return };
        let addr_bits = loaded.rom.address_bits;
        let Some(path) = rfd::FileDialog::new().add_filter("Scheme", &["txt", "TXT"]).pick_file() else {
            return;
        };
        let bytes = match std::fs::read(&path) {
            Ok(b) => b,
            Err(e) => {
                let msg = format!("failed to read {}: {e}", path.display());
                self.log(format!("{}: {msg}", t(self.lang, "Erro", "Error")));
                self.error = Some(msg);
                return;
            }
        };
        match parse_scheme_txt(&bytes, addr_bits) {
            Ok(scheme) => {
                self.manual_addr_map = scheme.addr_map;
                self.manual_data_map = scheme.data_map;
                self.scheme_comment = scheme.comment;
                self.error = None;
                self.refresh_displayed_bytes();
                self.log(format!("{}: {}", t(self.lang, "Esquema carregado", "Scheme loaded"), path.display()));
            }
            Err(e) => {
                self.log(format!("{}: {}", t(self.lang, "Erro ao carregar esquema", "Error loading scheme"), e));
                self.error = Some(e);
            }
        }
    }

    /// Saves the current manual address/data bit-wiring mapping as a
    /// `.txt` scheme file in the same community format `load_scheme` reads
    /// - see `scheme_txt`'s own doc comment for why the header identifies
    ///   Dec-ROM rather than the original application.
    fn save_scheme(&mut self) {
        let Some(path) = rfd::FileDialog::new().add_filter("Scheme", &["txt", "TXT"]).save_file() else {
            return;
        };
        match write_scheme_txt(&self.scheme_comment, &self.manual_addr_map, &self.manual_data_map) {
            Ok(bytes) => {
                if let Err(e) = std::fs::write(&path, bytes) {
                    let msg = format!("failed to write {}: {e}", path.display());
                    self.log(format!("{}: {msg}", t(self.lang, "Erro", "Error")));
                    self.error = Some(msg);
                } else {
                    self.error = None;
                    self.log(format!("{}: {}", t(self.lang, "Esquema salvo", "Scheme saved"), path.display()));
                }
            }
            Err(e) => {
                self.log(format!("{}: {}", t(self.lang, "Erro ao salvar esquema", "Error saving scheme"), e));
                self.error = Some(e);
            }
        }
    }
}

impl eframe::App for DecRomApp {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        if self.search.is_some() {
            self.poll_search();
            ui.ctx().request_repaint();
        }

        let mut action = None;
        let mut selection_changed = false;
        let mut manual_map_changed = false;

        egui::Panel::left("controls_panel").min_size(560.0).show(ui, |ui| {
            egui::ScrollArea::vertical().id_salt("controls_scroll").show(ui, |ui| {
                ui.horizontal(|ui| {
                    ui.heading("Dec-ROM");
                    if ui.button(t(self.lang, "Sobre...", "About...")).clicked() {
                        self.about_open = true;
                    }
                    ui.add_space(8.0);
                    ui.selectable_value(&mut self.lang, Lang::Pt, "PT");
                    ui.selectable_value(&mut self.lang, Lang::En, "EN");
                });

                if let Some(err) = &self.error {
                    ui.colored_label(egui::Color32::RED, err);
                }

                // Disabled while Auto-Fix is running: loading a new ROM
                // mid-search would leave the still-running search's result
                // (for the old ROM) to be silently applied on top of the
                // newly loaded one once it finishes - see `poll_search`.
                if ui
                    .add_enabled(self.search.is_none(), egui::Button::new(t(self.lang, "Carregar...", "Load...")))
                    .clicked()
                {
                    action = Some(Action::Load);
                }
                if let Some(loaded) = &self.loaded {
                    ui.label(format!(
                        "{} — {} ({} {})",
                        loaded.path.display(),
                        loaded.rom.eprom_type(),
                        loaded.rom.address_bits,
                        t(self.lang, "bits de endereço", "address bits")
                    ));
                }

                ui.horizontal(|ui| {
                    ui.label(t(self.lang, "Tempo máximo de busca:", "Search time limit:"));
                    egui::ComboBox::from_id_salt("time_budget_minutes")
                        .selected_text(format!("{} min", self.time_budget_minutes))
                        .show_ui(ui, |ui| {
                            for m in TIME_BUDGET_MINUTES_RANGE {
                                ui.selectable_value(&mut self.time_budget_minutes, m, format!("{m} min"));
                            }
                        });
                });

                let can_run = self.loaded.is_some() && self.search.is_none();
                if ui.add_enabled(can_run, egui::Button::new("Auto-Fix")).clicked() {
                    action = Some(Action::StartAutofix);
                }

                if let Some(result) = &self.result {
                    ui.separator();
                    match &result.confidence {
                        Confidence::High => {
                            ui.label(format!(
                                "{} — {}: {}, score: {:.3}, coverage: {:.3}",
                                t(self.lang, "Alta confiança", "High confidence"),
                                t(self.lang, "processador", "processor"),
                                result.processor.label(),
                                result.score,
                                result.coverage
                            ));
                        }
                        Confidence::Marginal(candidates) => {
                            ui.colored_label(
                                egui::Color32::ORANGE,
                                t(self.lang, "Confiança marginal — escolha um candidato:", "Marginal confidence — choose a candidate:"),
                            );
                            egui::ScrollArea::vertical().id_salt("candidates").max_height(200.0).show(ui, |ui| {
                                for (i, c) in candidates.iter().enumerate() {
                                    let text = format!(
                                        "{} — score: {:.3}, coverage: {:.3}",
                                        c.processor.label(),
                                        c.compression_score,
                                        c.coverage
                                    );
                                    if ui.radio_value(&mut self.selected_candidate, i, text).changed() {
                                        selection_changed = true;
                                    }
                                }
                            });
                        }
                    }
                }

                if let Some(loaded) = &self.loaded {
                    let addr_bits = loaded.rom.address_bits;
                    // Disabled while Auto-Fix is running so a manual edit
                    // can't race the background search's own writes to
                    // these same maps (see `sync_manual_from_result`).
                    let manual_controls_enabled = self.search.is_none();

                    ui.separator();
                    ui.label(t(self.lang, "Endereços (mapeamento manual):", "Addresses (manual mapping):"));
                    ui.add_enabled_ui(manual_controls_enabled, |ui| {
                        if bit_mapping_grid(ui, "addr_bit", "A", &mut self.manual_addr_map, addr_bits, 4) {
                            manual_map_changed = true;
                        }
                    });

                    ui.separator();
                    ui.label(t(self.lang, "Dados (mapeamento manual):", "Data (manual mapping):"));
                    ui.add_enabled_ui(manual_controls_enabled, |ui| {
                        if bit_mapping_grid(ui, "data_bit", "D", &mut self.manual_data_map, 8, 4) {
                            manual_map_changed = true;
                        }
                    });

                    ui.separator();
                    if ui
                        .add_enabled(manual_controls_enabled, egui::Button::new(t(self.lang, "Salvar...", "Save...")))
                        .clicked()
                    {
                        action = Some(Action::Save);
                    }

                    ui.separator();
                    ui.label(t(
                        self.lang,
                        "Esquema (.txt, formato A&L Software):",
                        "Scheme (.txt, A&L Software format):",
                    ));
                    ui.horizontal(|ui| {
                        ui.label(t(self.lang, "Comentários:", "Comments:"));
                        ui.text_edit_singleline(&mut self.scheme_comment);
                    });
                    ui.horizontal(|ui| {
                        if ui
                            .add_enabled(
                                manual_controls_enabled,
                                egui::Button::new(t(self.lang, "Carregar esquema...", "Load scheme...")),
                            )
                            .clicked()
                        {
                            action = Some(Action::LoadScheme);
                        }
                        if ui
                            .add_enabled(
                                manual_controls_enabled,
                                egui::Button::new(t(self.lang, "Salvar esquema...", "Save scheme...")),
                            )
                            .clicked()
                        {
                            action = Some(Action::SaveScheme);
                        }
                    });

                    ui.separator();
                    ui.label(t(self.lang, "Log:", "Log:"));
                    let progress = self.search.is_some().then_some((self.progress.0, self.progress.1.as_str()));
                    log_panel(ui, &self.log_lines, progress);
                }
            });
        });

        egui::CentralPanel::default().show(ui, |ui| {
            ui.label("Hex:");
            hex_view(ui, &self.displayed_bytes);
        });

        let mut about_open = self.about_open;
        // `.id(...)` pins the window's identity independent of its title,
        // since egui otherwise uses the title itself as the Id - without
        // this, toggling the PT/EN language selector while this window is
        // open would change its title and reset its position/size as if it
        // were a brand-new window.
        egui::Window::new(t(self.lang, "Sobre o Dec-ROM", "About Dec-ROM"))
            .id(egui::Id::new("about_window"))
            .open(&mut about_open)
            .collapsible(false)
            .resizable(false)
            .show(ui.ctx(), |ui| {
                ui.label(t(
                    self.lang,
                    "Dec-ROM — Reorganizador de bits de EPROM",
                    "Dec-ROM — EPROM Bit Reorganizer",
                ));
                ui.label(t(self.lang, "Criado por Pakequis", "Created by Pakequis"));
                ui.hyperlink("https://www.github.com/pakequis");
            });
        self.about_open = about_open;

        match action {
            Some(Action::Load) => self.load_rom(),
            Some(Action::StartAutofix) => self.start_autofix(),
            Some(Action::Save) => self.save_mapping(),
            Some(Action::LoadScheme) => self.load_scheme(),
            Some(Action::SaveScheme) => self.save_scheme(),
            None => {}
        }
        if selection_changed {
            self.sync_manual_from_result();
        }
        if manual_map_changed {
            self.refresh_displayed_bytes();
        }
    }
}

/// Renders `target.len()` bit-source dropdowns (e.g. "A3 <- A7") as a grid
/// with `cols` pairs per row, wrapping to a new row every `cols` entries -
/// keeps the manual address mapping (up to 16 rows for a 64KB ROM) from
/// growing tall enough to push the save/scheme buttons below the fold (see
/// the "single window size, no left-side scrollbar" backlog item). Each
/// label is a fixed size regardless of digit count, so columns stay
/// aligned even past index 9 (e.g. "A10").
fn bit_mapping_grid(ui: &mut egui::Ui, id_source: &str, prefix: &str, target: &mut [u32], source_count: u32, cols: usize) -> bool {
    let mut changed = false;
    egui::Grid::new(id_source).show(ui, |ui| {
        for (i, val) in target.iter_mut().enumerate() {
            ui.horizontal(|ui| {
                let label_height = ui.spacing().interact_size.y;
                ui.add_sized([36.0, label_height], egui::Label::new(format!("{prefix}{i} <-")));
                egui::ComboBox::from_id_salt(format!("{id_source}_{i}"))
                    .selected_text(format!("{prefix}{val}"))
                    .show_ui(ui, |ui| {
                        for src in 0..source_count {
                            if ui.selectable_value(val, src, format!("{prefix}{src}")).changed() {
                                changed = true;
                            }
                        }
                    });
            });
            if (i + 1) % cols == 0 {
                ui.end_row();
            }
        }
    });
    changed
}

/// Renders a classic ASCII `[####----] NN%` progress bar of `width`
/// characters between the brackets.
fn ascii_progress_bar(pct: u32, width: usize) -> String {
    let pct = pct.min(100);
    let filled = (pct as usize * width) / 100;
    format!("[{}{}] {pct:3}%", "#".repeat(filled), "-".repeat(width - filled))
}

/// Renders `lines` as a read-only scrolling log in a fixed-height scroll
/// area, so it never grows the controls panel past what fits in the
/// window (see the "single window size, no left-side scrollbar" backlog
/// item) - like the hex view, this one keeps its own scrollbar. Uses the
/// same monospace/default-color/background styling as `hex_view` rather
/// than a distinct terminal palette, per the user's request. While
/// `progress` is `Some((pct, message))`, an extra ASCII progress-bar line
/// is drawn after the log history - replacing the previous
/// `egui::ProgressBar` widget, at the user's request - and re-rendered
/// each frame rather than appended to `lines`, so it updates in place
/// instead of spamming the history with one line per tick.
fn log_panel(ui: &mut egui::Ui, lines: &VecDeque<String>, progress: Option<(u32, &str)>) {
    egui::ScrollArea::vertical().id_salt("log_scroll").max_height(140.0).stick_to_bottom(true).show(ui, |ui| {
        for line in lines {
            ui.monospace(line);
        }
        if let Some((pct, msg)) = progress {
            ui.monospace(format!("{} {msg}", ascii_progress_bar(pct, 24)));
        }
    });
}

/// Renders `data` as a classic hex dump - 8-digit offset, 16 bytes per row
/// in two groups of 8, ASCII alongside - using a virtualized scroll area
/// (`show_rows`) so only the visible rows are ever laid out, regardless of
/// how large `data` is (up to `reorganizer::MAX_FILE_SIZE`, 64KB).
fn hex_view(ui: &mut egui::Ui, data: &[u8]) {
    let row_height = ui.text_style_height(&egui::TextStyle::Monospace);
    let total_rows = data.len().div_ceil(16);
    egui::ScrollArea::vertical().id_salt("hex_view").auto_shrink([false, false]).show_rows(
        ui,
        row_height,
        total_rows,
        |ui, row_range| {
            for row in row_range {
                let offset = row * 16;
                let chunk = &data[offset..(offset + 16).min(data.len())];
                let mut left = String::new();
                let mut right = String::new();
                let mut ascii = String::new();
                for (i, &b) in chunk.iter().enumerate() {
                    if i < 8 {
                        left.push_str(&format!("{b:02X} "));
                    } else {
                        right.push_str(&format!("{b:02X} "));
                    }
                    ascii.push(if (0x20..=0x7e).contains(&b) { b as char } else { '.' });
                }
                ui.monospace(format!("{offset:08X}  {left:<24}{right:<24} {ascii}"));
            }
        },
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use dec_rom::autofix::Candidate;
    use dec_rom::detectors::Processor;

    fn candidate(addr_map: Vec<u32>, data_map: [u32; 8]) -> Candidate {
        Candidate { addr_map, data_map, processor: Processor::Z80, compression_score: 0.0, coverage: 0.0, preview: Vec::new() }
    }

    #[test]
    fn sync_manual_from_result_follows_the_selected_marginal_candidate() {
        let data = vec![0x10, 0x32, 0x54, 0x76, 0x98, 0xBA, 0xDC, 0xFE];
        let identity_map: Vec<u32> = (0..3).collect();
        let reversed_map: Vec<u32> = (0..3).rev().collect();

        let mut app = DecRomApp {
            loaded: Some(LoadedRom { path: PathBuf::new(), rom: Rom { data: data.clone(), address_bits: 3 } }),
            result: Some(AutoFixResult {
                processor: Processor::Z80,
                addr_map: identity_map.clone(),
                data_map: IDENTITY_DATA_MAP,
                score: 0.0,
                coverage: 0.0,
                confidence: Confidence::Marginal(vec![
                    candidate(identity_map, IDENTITY_DATA_MAP),
                    candidate(reversed_map, IDENTITY_DATA_MAP),
                ]),
                elapsed: Duration::ZERO,
                max_k_covered: 0,
                ascending_k_complete: true,
            }),
            ..Default::default()
        };

        app.selected_candidate = 0;
        app.sync_manual_from_result();
        let identity_view = app.displayed_bytes.clone();
        assert_eq!(identity_view, data, "candidate 0 is the identity mapping, should show the raw bytes unchanged");

        app.selected_candidate = 1;
        app.sync_manual_from_result();
        assert_ne!(
            app.displayed_bytes, identity_view,
            "selecting a different candidate must change what the hex view shows"
        );
    }

    #[test]
    fn manually_editing_the_address_map_changes_the_displayed_bytes() {
        let data = vec![0x10, 0x32, 0x54, 0x76, 0x98, 0xBA, 0xDC, 0xFE];
        let mut app = DecRomApp {
            loaded: Some(LoadedRom { path: PathBuf::new(), rom: Rom { data: data.clone(), address_bits: 3 } }),
            manual_addr_map: (0..3).collect(),
            manual_data_map: IDENTITY_DATA_MAP,
            ..Default::default()
        };
        app.refresh_displayed_bytes();
        assert_eq!(app.displayed_bytes, data);

        app.manual_addr_map = (0..3).rev().collect();
        app.refresh_displayed_bytes();
        assert_ne!(app.displayed_bytes, data, "editing the manual address map by hand must change the hex view");
    }
}
