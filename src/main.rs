#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod api;
mod app;
mod config;
mod upload_queue;
mod watcher;

use eframe::egui;

fn main() -> anyhow::Result<()> {
    let icon = load_icon();

    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([500.0, 650.0])
            .with_min_inner_size([400.0, 500.0])
            .with_icon(icon.unwrap_or_default()),
        ..Default::default()
    };

    let title = format!("Ballchasing Uploader v{}", env!("CARGO_PKG_VERSION"));

    eframe::run_native(
        &title,
        options,
        Box::new(|_cc| Box::new(app::UploaderApp::new())),
    )
    .map_err(|e| anyhow::anyhow!("{}", e))?;

    Ok(())
}

fn load_icon() -> Option<egui::IconData> {
    let icon_run = || -> anyhow::Result<egui::IconData> {
        let icon_bytes = include_bytes!("../LogoA.png");
        let image = image::load_from_memory(icon_bytes)?.to_rgba8();
        let (width, height) = image.dimensions();
        Ok(egui::IconData {
            rgba: image.into_raw(),
            width,
            height,
        })
    };

    Some(icon_run().unwrap_or_default())
}
