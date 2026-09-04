//! Binary entry point: launches the egui GUI (see `ui.rs`).

// Release builds on Windows are GUI apps: suppress the console window that
// would otherwise open behind the window. Debug builds keep the console so
// panic output and logging stay visible during development.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod ui;

/// A light theme approximating a native Windows look (light gray
/// window/panel background, Windows' own accent blue for selection and
/// links) instead of egui's default dark theme.
fn windows_light_visuals() -> egui::Visuals {
    let mut visuals = egui::Visuals::light();
    let window_gray = egui::Color32::from_rgb(0xF0, 0xF0, 0xF0);
    let accent_blue = egui::Color32::from_rgb(0x00, 0x78, 0xD4);
    visuals.window_fill = window_gray;
    visuals.panel_fill = window_gray;
    visuals.faint_bg_color = egui::Color32::from_rgb(0xE8, 0xE8, 0xE8);
    visuals.selection.bg_fill = accent_blue;
    visuals.selection.stroke = egui::Stroke::new(1.0, egui::Color32::WHITE);
    visuals.hyperlink_color = accent_blue;
    visuals
}

fn main() -> eframe::Result {
    let native_options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default().with_inner_size([1250.0, 1000.0]).with_resizable(false),
        ..Default::default()
    };
    eframe::run_native(
        "Dec-ROM",
        native_options,
        Box::new(|cc| {
            cc.egui_ctx.set_visuals(windows_light_visuals());
            Ok(Box::new(ui::DecRomApp::default()))
        }),
    )
}
