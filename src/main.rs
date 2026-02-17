#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod api;
mod config;
mod upload_queue;
mod watcher;
mod app;

use eframe::egui;

fn main() -> anyhow::Result<()> {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([500.0, 650.0])
            .with_min_inner_size([400.0, 500.0]),
        ..Default::default()
    };

    eframe::run_native(
        "Ballchasing Uploader",
        options,
        Box::new(|_cc| Box::new(app::UploaderApp::new())),
    )
    .map_err(|e| anyhow::anyhow!("{}", e))?;

    Ok(())
}
