use eframe::egui;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::api;
use crate::config;
use crate::upload_queue;
use crate::watcher;

#[derive(Debug, Clone, PartialEq)]
pub enum ApiKeyStatus {
    Unknown,
    Verifying,
    Valid { name: String, account_type: String },
    Invalid(String),
}

#[derive(Debug, Clone, PartialEq)]
pub enum AppTab {
    Dashboard,
    Settings,
}

#[derive(Debug, Clone)]
pub struct UploadLogEntry {
    pub file_name: String,
    pub status: UploadLogStatus,
    pub time: String,
}

#[derive(Debug, Clone)]
pub enum UploadLogStatus {
    Uploading,
    Success(String),
    Duplicate,
    Failed(String),
}

pub struct UploaderState {
    // API Key
    pub api_key_input: String,
    pub show_api_key: bool,
    pub api_key_status: ApiKeyStatus,

    // Tabs
    pub current_tab: AppTab,

    // Config & persistence
    pub config: config::UploaderConfig,
    pub config_path: PathBuf,

    // Upload settings
    pub auto_upload: bool,
    pub watcher_active: bool,

    // Upload log
    pub upload_log: Vec<UploadLogEntry>,

    // Status bar
    pub status_message: String,

    // Auto-update
    pub update_available: Option<String>,
    pub update_dismissed: bool,
    pub update_status: Option<String>,
    pub update_in_progress: bool,
}

impl UploaderState {
    pub fn new() -> Self {
        let config_path = config::default_config_path();
        let cfg = config::UploaderConfig::load(&config_path);

        let current_tab = AppTab::Dashboard;

        let api_key_input = cfg.api_key.clone();

        Self {
            api_key_input,
            show_api_key: false,
            api_key_status: ApiKeyStatus::Unknown,
            current_tab,
            config: cfg,
            config_path,
            auto_upload: true,
            watcher_active: false,
            upload_log: Vec::new(),
            status_message: "Idle".to_string(),
            update_available: None,
            update_dismissed: false,
            update_status: None,
            update_in_progress: false,
        }
    }

    pub fn add_log(&mut self, entry: UploadLogEntry) {
        self.upload_log.insert(0, entry);
        if self.upload_log.len() > 20 {
            self.upload_log.truncate(20);
        }
    }

    pub fn update_log(&mut self, file_name: &str, status: UploadLogStatus) {
        let time = chrono::Local::now().format("%H:%M:%S").to_string();
        if let Some(entry) = self
            .upload_log
            .iter_mut()
            .find(|e| e.file_name == file_name)
        {
            entry.status = status;
            entry.time = time;
        } else {
            self.upload_log.insert(
                0,
                UploadLogEntry {
                    file_name: file_name.to_string(),
                    status,
                    time,
                },
            );
            if self.upload_log.len() > 20 {
                self.upload_log.truncate(20);
            }
        }
    }

    pub fn configured_watch_dirs(&self) -> Vec<PathBuf> {
        self.config.watch_dirs.clone()
    }
}

fn tier_display(account_type: &str) -> (&str, &str) {
    match account_type {
        "regular" => ("Regular", "2 uploads/sec"),
        "gold" => ("Gold", "4 uploads/sec"),
        "diamond" => ("Diamond", "8 uploads/sec"),
        "champion" => ("Champion", "8 uploads/sec"),
        "gc" => ("Grand Champion", "16 uploads/sec"),
        _ => ("Unknown", "Unknown limits"),
    }
}

struct RenderSnapshot {
    api_key_input: String,
    show_api_key: bool,
    api_key_status: ApiKeyStatus,
    current_tab: AppTab,
    visibility: config::Visibility,
    auto_upload: bool,
    watcher_active: bool,
    upload_log: Vec<UploadLogEntry>,
    status_message: String,
    update_available: Option<String>,
    update_dismissed: bool,
    update_status: Option<String>,
    update_in_progress: bool,
}

pub struct UploaderApp {
    state: Arc<Mutex<UploaderState>>,
}

impl UploaderApp {
    pub fn new() -> Self {
        let state = Arc::new(Mutex::new(UploaderState::new()));

        {
            let s = state.lock().unwrap_or_else(|p| p.into_inner());
            if !s.api_key_input.is_empty() {
                let key = s.api_key_input.clone();
                let state_clone = state.clone();
                drop(s);
                {
                    let mut s = state_clone.lock().unwrap_or_else(|p| p.into_inner());
                    s.api_key_status = ApiKeyStatus::Verifying;
                }
                std::thread::spawn(move || {
                    let client = api::BallchasingClient::new(&key);
                    match client.ping() {
                        Ok(info) => {
                            let mut s = state_clone.lock().unwrap_or_else(|p| p.into_inner());
                            s.api_key_status = ApiKeyStatus::Valid {
                                name: info.name,
                                account_type: info.account_type,
                            };
                        }
                        Err(e) => {
                            let mut s = state_clone.lock().unwrap_or_else(|p| p.into_inner());
                            s.api_key_status = ApiKeyStatus::Invalid(format!("{}", e));
                        }
                    }
                });
            }
        }

        {
            let state_clone = state.clone();
            std::thread::spawn(move || {
                let (api_key, config_path) = {
                    let s = state_clone.lock().unwrap_or_else(|p| p.into_inner());
                    (s.config.api_key.clone(), s.config_path.clone())
                };
                if api_key.is_empty() {
                    return;
                }
                let data_dir = config_path
                    .parent()
                    .unwrap_or(&PathBuf::from("."))
                    .to_path_buf();
                let queue_path = data_dir.join("upload_queue.json");
                let mut queue = upload_queue::UploadQueue::load(&queue_path);
                queue.prune_expired();
                let count = queue.pending().len();
                if count > 0 {
                    let mut s = state_clone.lock().unwrap_or_else(|p| p.into_inner());
                    s.status_message = format!("Retrying {} pending upload(s)...", count);
                }
            });
        }

        // Background Update Checker
        {
            let state_clone = state.clone();
            std::thread::spawn(move || {
                match self_update::backends::github::Update::configure()
                    .repo_owner("Aylian-Studios")
                    .repo_name("ballchasing-uploader")
                    .bin_name("ballchasing-uploader")
                    .current_version(env!("CARGO_PKG_VERSION"))
                    .build()
                {
                    Ok(updater) => {
                        if let Ok(latest) = updater.get_latest_release() {
                            if self_update::version::bump_is_greater(
                                env!("CARGO_PKG_VERSION"),
                                &latest.version,
                            )
                            .unwrap_or(false)
                            {
                                let mut s = state_clone.lock().unwrap_or_else(|p| p.into_inner());
                                s.update_available = Some(latest.version);
                            }
                        }
                    }
                    Err(e) => eprintln!("Update check failed: {}", e),
                }
            });
        }

        if state.lock().unwrap().auto_upload {
            let app = Self {
                state: state.clone(),
            };
            app.start_watcher();
            return app;
        }

        Self { state }
    }

    fn start_watcher(&self) {
        let mut s = self.state.lock().unwrap_or_else(|p| p.into_inner());

        if s.watcher_active {
            eprintln!("Auto-upload: already active");
            return;
        }

        let has_key = !s.config.api_key.is_empty();
        let has_folders = !s.config.watch_dirs.is_empty();

        if !has_key {
            eprintln!("Auto-upload abort: No API key configured");
            s.status_message = "Verify your API key first".to_string();
            s.auto_upload = false;
            return;
        }

        if !has_folders {
            eprintln!("Auto-upload abort: No replay folders configured");
            s.status_message = "Add a replay folder first".to_string();
            s.auto_upload = false;
            return;
        }

        let watch_dirs = s.config.watch_dirs.clone();
        let api_key = s.config.api_key.clone();
        let visibility = s.config.visibility.as_str().to_string();
        let state_clone = self.state.clone();
        let config_path = s.config_path.clone();

        match watcher::watch_directories(&watch_dirs) {
            Ok(rx) => {
                s.watcher_active = true;
                s.status_message =
                    format!("Watching {} folders for new replays...", watch_dirs.len());
                drop(s);

                std::thread::spawn(move || {
                    let client = api::BallchasingClient::new(&api_key);

                    loop {
                        match rx.recv() {
                            Ok(path) => {
                                // Check if we should still be running
                                {
                                    let s = state_clone.lock().unwrap_or_else(|p| p.into_inner());
                                    if !s.auto_upload {
                                        break;
                                    }
                                }
                                process_new_file(
                                    &client,
                                    &path,
                                    &visibility,
                                    &state_clone,
                                    &config_path,
                                );
                            }
                            Err(_) => break,
                        }
                    }

                    let mut s = state_clone.lock().unwrap_or_else(|p| p.into_inner());
                    s.watcher_active = false;
                    s.status_message = "Idle".to_string();
                });
            }
            Err(e) => {
                s.status_message = format!("Watcher error: {}", e);
                s.auto_upload = false;
            }
        }
    }
}

impl eframe::App for UploaderApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        let snap = {
            let s = self.state.lock().unwrap_or_else(|p| p.into_inner());
            RenderSnapshot {
                api_key_input: s.api_key_input.clone(),
                show_api_key: s.show_api_key,
                api_key_status: s.api_key_status.clone(),
                current_tab: s.current_tab.clone(),
                visibility: s.config.visibility.clone(),
                auto_upload: s.auto_upload,
                watcher_active: s.watcher_active,
                upload_log: s.upload_log.clone(),
                status_message: s.status_message.clone(),
                update_available: s.update_available.clone(),
                update_dismissed: s.update_dismissed,
                update_status: s.update_status.clone(),
                update_in_progress: s.update_in_progress,
            }
        };

        // Branding Footer (Must be added before CentralPanel)
        egui::TopBottomPanel::bottom("footer").show(ctx, |ui| {
            ui.add_space(4.0);
            ui.horizontal(|ui| {
                ui.label(
                    egui::RichText::new(format!("v{}", env!("CARGO_PKG_VERSION")))
                        .weak()
                        .small(),
                );

                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    ui.hyperlink_to("Aylian Studios", "https://aylian-studios.com");
                    ui.label(egui::RichText::new("Built by ").weak());

                    ui.separator();

                    ui.hyperlink_to(
                        "GitHub",
                        "https://github.com/Aylian-Studios/ballchasing-uploader",
                    );
                    ui.label("|");
                    ui.hyperlink_to(
                        "Project Page",
                        "https://aylian-studios.com/projects/ballchasing-uploader",
                    );

                    ui.separator();

                    if ui.link("Check for Updates").clicked() {
                        let _ = open::that(
                            "https://github.com/Aylian-Studios/ballchasing-uploader/releases",
                        );
                    }
                });
            });
            ui.add_space(2.0);
        });

        if let Some(version) = &snap.update_available {
            if !snap.update_dismissed {
                egui::TopBottomPanel::top("update_banner").show(ctx, |ui| {
                    ui.add_space(8.0);
                    ui.horizontal(|ui| {
                        if snap.update_in_progress {
                            ui.spinner();
                            ui.label(
                                egui::RichText::new(format!("Downloading update v{}...", version))
                                    .strong(),
                            );
                            if let Some(status) = &snap.update_status {
                                ui.label(egui::RichText::new(status).weak());
                            }
                        } else {
                            ui.label(
                                egui::RichText::new(format!("Update v{} is available!", version))
                                    .strong()
                                    .color(egui::Color32::from_rgb(100, 200, 255)),
                            );
                            ui.with_layout(
                                egui::Layout::right_to_left(egui::Align::Center),
                                |ui| {
                                    if ui.button("❌").on_hover_text("Close").clicked() {
                                        let mut s =
                                            self.state.lock().unwrap_or_else(|p| p.into_inner());
                                        s.update_dismissed = true;
                                    }
                                    ui.add_space(4.0);
                                    if ui.button("Remind me later").clicked() {
                                        let mut s =
                                            self.state.lock().unwrap_or_else(|p| p.into_inner());
                                        s.update_dismissed = true;
                                    }
                                    ui.add_space(4.0);
                                    if ui
                                        .button(
                                            egui::RichText::new("Install Now")
                                                .color(egui::Color32::WHITE),
                                        )
                                        .clicked()
                                    {
                                        let state_clone = self.state.clone();
                                        {
                                            let mut s = self
                                                .state
                                                .lock()
                                                .unwrap_or_else(|p| p.into_inner());
                                            s.update_in_progress = true;
                                            s.update_status =
                                                Some("Starting download...".to_string());
                                        }
                                        std::thread::spawn(move || {
                                            let status_update = |msg: &str| {
                                                let mut s = state_clone
                                                    .lock()
                                                    .unwrap_or_else(|p| p.into_inner());
                                                s.update_status = Some(msg.to_string());
                                            };

                                            let update_result =
                                                self_update::backends::github::Update::configure()
                                                    .repo_owner("Aylian-Studios")
                                                    .repo_name("ballchasing-uploader")
                                                    .bin_name("ballchasing-uploader")
                                                    .show_download_progress(false)
                                                    .current_version(env!("CARGO_PKG_VERSION"))
                                                    .build()
                                                    .and_then(|updater| updater.update());

                                            match update_result {
                                                Ok(status) => {
                                                    status_update(&format!(
                                                        "Updated to {}! Restarting...",
                                                        status.version()
                                                    ));
                                                    std::thread::sleep(Duration::from_secs(1));

                                                    if let Ok(current_exe) = std::env::current_exe()
                                                    {
                                                        let _ =
                                                            std::process::Command::new(current_exe)
                                                                .spawn();
                                                        std::process::exit(0);
                                                    }
                                                }
                                                Err(e) => {
                                                    let mut s = state_clone
                                                        .lock()
                                                        .unwrap_or_else(|p| p.into_inner());
                                                    s.update_in_progress = false;
                                                    s.update_status = Some(format!("Error: {}", e));
                                                }
                                            }
                                        });
                                    }
                                },
                            );
                        }
                    });
                    ui.add_space(8.0);
                });
            }
        }

        egui::CentralPanel::default().show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.heading("Ballchasing Uploader");
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if ui
                        .selectable_label(snap.current_tab == AppTab::Settings, "⚙ Settings")
                        .clicked()
                    {
                        let mut s = self.state.lock().unwrap_or_else(|p| p.into_inner());
                        s.current_tab = AppTab::Settings;
                    }
                    if ui
                        .selectable_label(snap.current_tab == AppTab::Dashboard, "📊 Dashboard")
                        .clicked()
                    {
                        let mut s = self.state.lock().unwrap_or_else(|p| p.into_inner());
                        s.current_tab = AppTab::Dashboard;
                    }
                });
            });
            ui.label(
                egui::RichText::new(format!(
                    "v{} — Auto-upload replays to ballchasing.com",
                    env!("CARGO_PKG_VERSION")
                ))
                .weak()
                .small(),
            );
            ui.separator();
            ui.add_space(4.0);

            match snap.current_tab {
                AppTab::Dashboard => {
                    self.render_api_key_section(ui, &snap);
                    ui.add_space(4.0);

                    if let ApiKeyStatus::Valid {
                        ref name,
                        ref account_type,
                    } = snap.api_key_status
                    {
                        let (tier_name, rate_info) = tier_display(account_type);
                        ui.group(|ui| {
                            ui.horizontal(|ui| {
                                ui.label(
                                    egui::RichText::new(format!("Account: {}", name)).strong(),
                                );
                                ui.separator();
                                ui.label(format!("Tier: {}", tier_name));
                                ui.separator();
                                ui.label(
                                    egui::RichText::new(format!("Rate: {}", rate_info)).weak(),
                                );
                            });
                        });
                        ui.add_space(4.0);
                    }

                    ui.separator();
                    ui.add_space(4.0);
                    self.render_upload_settings(ui, &snap);
                    ui.add_space(4.0);
                    ui.separator();
                    ui.add_space(4.0);

                    self.render_upload_log(ui, &snap);
                }
                AppTab::Settings => {
                    self.render_settings_tab(ui, &snap);
                }
            }

            ui.add_space(8.0);
            ui.separator();
            if snap.watcher_active {
                ui.label(
                    egui::RichText::new(&snap.status_message)
                        .color(egui::Color32::GREEN)
                        .small(),
                );
            } else {
                ui.label(egui::RichText::new(&snap.status_message).weak().small());
            }
        });

        ctx.request_repaint_after(Duration::from_millis(250));
    }
}

impl UploaderApp {
    fn render_api_key_section(&self, ui: &mut egui::Ui, snap: &RenderSnapshot) {
        ui.label(egui::RichText::new("API Key").strong());
        ui.label(
            egui::RichText::new("Get your key at ballchasing.com/upload")
                .weak()
                .small(),
        );
        ui.add_space(2.0);

        let mut key_input = snap.api_key_input.clone();
        ui.horizontal(|ui| {
            let response = ui.add(
                egui::TextEdit::singleline(&mut key_input)
                    .password(!snap.show_api_key)
                    .desired_width(280.0)
                    .hint_text("Paste your API key here"),
            );
            if response.changed() {
                let mut s = self.state.lock().unwrap_or_else(|p| p.into_inner());
                s.api_key_input = key_input.clone();
            }

            let eye_label = if snap.show_api_key { "Hide" } else { "Show" };
            if ui.button(eye_label).clicked() {
                let mut s = self.state.lock().unwrap_or_else(|p| p.into_inner());
                s.show_api_key = !s.show_api_key;
            }

            if ui.button("Verify").clicked() {
                let state_clone = self.state.clone();
                let key = key_input.clone();
                {
                    let mut s = self.state.lock().unwrap_or_else(|p| p.into_inner());
                    s.config.api_key = key.clone();
                    s.api_key_status = ApiKeyStatus::Verifying;
                    let _ = s.config.save(&s.config_path);
                }
                std::thread::spawn(move || {
                    let client = api::BallchasingClient::new(&key);
                    match client.ping() {
                        Ok(info) => {
                            let mut s = state_clone.lock().unwrap_or_else(|p| p.into_inner());
                            s.api_key_status = ApiKeyStatus::Valid {
                                name: info.name,
                                account_type: info.account_type,
                            };
                        }
                        Err(e) => {
                            let mut s = state_clone.lock().unwrap_or_else(|p| p.into_inner());
                            s.api_key_status = ApiKeyStatus::Invalid(format!("{}", e));
                        }
                    }
                });
            }
        });

        ui.add_space(2.0);
        match &snap.api_key_status {
            ApiKeyStatus::Unknown => {
                ui.label(egui::RichText::new("Not verified").weak().small());
            }
            ApiKeyStatus::Verifying => {
                ui.horizontal(|ui| {
                    ui.spinner();
                    ui.label("Verifying...");
                });
            }
            ApiKeyStatus::Valid { name, .. } => {
                ui.label(
                    egui::RichText::new(format!("Verified: {}", name))
                        .color(egui::Color32::GREEN)
                        .small(),
                );
            }
            ApiKeyStatus::Invalid(err) => {
                ui.label(
                    egui::RichText::new(format!("Invalid: {}", err))
                        .color(egui::Color32::RED)
                        .small(),
                );
            }
        }
    }

    fn render_settings_tab(&self, ui: &mut egui::Ui, _snap: &RenderSnapshot) {
        egui::ScrollArea::vertical().show(ui, |ui| {
            ui.label(egui::RichText::new("Replay Folders").strong());
            ui.add_space(2.0);

            let watch_dirs = {
                let s = self.state.lock().unwrap_or_else(|p| p.into_inner());
                s.config.watch_dirs.clone()
            };

            for (idx, dir) in watch_dirs.clone().into_iter().enumerate() {
                ui.horizontal(|ui| {
                    if dir.exists() {
                        ui.label(egui::RichText::new("✓").color(egui::Color32::GREEN));
                    } else {
                        ui.label(egui::RichText::new("⚠").color(egui::Color32::RED));
                    }
                    ui.label(
                        egui::RichText::new(dir.display().to_string())
                            .weak()
                            .monospace()
                            .small(),
                    );
                    if ui.button("Remove").clicked() {
                        let mut s = self.state.lock().unwrap_or_else(|p| p.into_inner());
                        s.config.watch_dirs.remove(idx);
                        let _ = s.config.save(&s.config_path);
                    }
                });
            }

            ui.add_space(4.0);
            if ui.button("Add Folder...").clicked() {
                let state_clone = self.state.clone();
                std::thread::spawn(move || {
                    if let Some(folder) = rfd::FileDialog::new().pick_folder() {
                        let mut s = state_clone.lock().unwrap_or_else(|p| p.into_inner());
                        if !s.config.watch_dirs.contains(&folder) {
                            s.config.watch_dirs.push(folder);
                            let _ = s.config.save(&s.config_path);
                        }
                    }
                });
            }

            ui.add_space(12.0);
            ui.separator();
            ui.add_space(12.0);

            ui.label(egui::RichText::new("BakkesMod Settings").strong());
            ui.add_space(4.0);

            let mut s = self.state.lock().unwrap_or_else(|p| p.into_inner());
            let mut save_needed = false;

            let mut enable_safe_mode = s.config.enable_safe_mode;
            if ui
                .checkbox(&mut enable_safe_mode, "Enable safe mode")
                .changed()
            {
                s.config.enable_safe_mode = enable_safe_mode;
                save_needed = true;
            }

            let mut run_on_startup = s.config.run_on_startup;
            if ui.checkbox(&mut run_on_startup, "Run on startup").changed() {
                s.config.run_on_startup = run_on_startup;
                save_needed = true;

                if let Ok(current_exe) = std::env::current_exe() {
                    let app_name = "BallchasingUploader";
                    if let Ok(auto) = auto_launch::AutoLaunchBuilder::new()
                        .set_app_name(app_name)
                        .set_app_path(&current_exe.to_string_lossy())
                        .set_macos_launch_mode(auto_launch::MacOSLaunchMode::LaunchAgent)
                        .build()
                    {
                        if run_on_startup {
                            let _ = auto.enable();
                        } else {
                            let _ = auto.disable();
                        }
                    }
                }
            }

            let mut hide_when_minimized = s.config.hide_when_minimized;
            if ui
                .checkbox(&mut hide_when_minimized, "Hide when minimized")
                .changed()
            {
                s.config.hide_when_minimized = hide_when_minimized;
                save_needed = true;
            }

            let mut minimize_on_start = s.config.minimize_on_start;
            if ui
                .checkbox(&mut minimize_on_start, "Minimize on start")
                .changed()
            {
                s.config.minimize_on_start = minimize_on_start;
                save_needed = true;
            }

            let mut disable_warnings = s.config.disable_warnings;
            if ui
                .checkbox(&mut disable_warnings, "Disable warnings")
                .changed()
            {
                s.config.disable_warnings = disable_warnings;
                save_needed = true;
            }

            if save_needed {
                let _ = s.config.save(&s.config_path);
            }
        });
    }

    fn render_upload_settings(&self, ui: &mut egui::Ui, snap: &RenderSnapshot) {
        ui.label(egui::RichText::new("Upload Settings").strong());
        ui.add_space(2.0);

        ui.horizontal(|ui| {
            ui.label("Visibility:");
            let current_label = snap.visibility.as_str();
            egui::ComboBox::from_id_source("visibility_select")
                .width(100.0)
                .selected_text(current_label)
                .show_ui(ui, |ui| {
                    let options = [
                        ("public", "Public"),
                        ("unlisted", "Unlisted"),
                        ("private", "Private"),
                    ];
                    for (value, label) in &options {
                        if ui
                            .selectable_label(current_label == *value, *label)
                            .clicked()
                        {
                            let mut s = self.state.lock().unwrap_or_else(|p| p.into_inner());
                            if let Ok(vis) = value.parse::<config::Visibility>() {
                                s.config.visibility = vis;
                                let _ = s.config.save(&s.config_path);
                            }
                        }
                    }
                });
        });

        ui.add_space(4.0);

        let mut auto_upload = snap.auto_upload;
        if ui
            .checkbox(&mut auto_upload, "Auto-upload replays")
            .changed()
        {
            let mut s = self.state.lock().unwrap_or_else(|p| p.into_inner());
            s.auto_upload = auto_upload;

            if auto_upload {
                drop(s);
                self.start_watcher();
            } else {
                s.status_message = "Idle".to_string();
            }
        }
        if snap.watcher_active {
            ui.label(
                egui::RichText::new("Watcher active")
                    .color(egui::Color32::GREEN)
                    .small(),
            );
        }
    }

    fn render_upload_log(&self, ui: &mut egui::Ui, snap: &RenderSnapshot) {
        ui.label(egui::RichText::new("Recent Uploads").strong());
        ui.add_space(2.0);

        if snap.upload_log.is_empty() {
            ui.label(egui::RichText::new("No uploads yet").weak().italics());
        } else {
            egui::ScrollArea::vertical()
                .max_height(200.0)
                .show(ui, |ui| {
                    for entry in &snap.upload_log {
                        ui.vertical(|ui| {
                            ui.horizontal(|ui| {
                                let (color, icon) = match &entry.status {
                                    UploadLogStatus::Uploading => (egui::Color32::YELLOW, "..."),
                                    UploadLogStatus::Success(_) => (egui::Color32::GREEN, "[ok]"),
                                    UploadLogStatus::Duplicate => (egui::Color32::GRAY, "[dup]"),
                                    UploadLogStatus::Failed(_) => (egui::Color32::RED, "[!]"),
                                };
                                ui.colored_label(color, icon);
                                ui.label(egui::RichText::new(&entry.file_name).small());
                                ui.label(egui::RichText::new(&entry.time).weak().small());
                            });
                            if let UploadLogStatus::Failed(ref err) = entry.status {
                                ui.label(
                                    egui::RichText::new(format!("    {}", err))
                                        .color(egui::Color32::RED)
                                        .small(),
                                );
                            }
                        });
                    }
                });
        }
    }
}

fn try_exclusive_access(path: &PathBuf) -> bool {
    #[cfg(target_os = "windows")]
    {
        use std::fs::OpenOptions;
        OpenOptions::new().read(true).write(true).open(path).is_ok()
    }
    #[cfg(not(target_os = "windows"))]
    {
        path.exists()
    }
}

fn wait_for_file_stable(path: &PathBuf) -> bool {
    std::thread::sleep(Duration::from_secs(2));

    for _ in 0..20 {
        if try_exclusive_access(path) {
            let size1 = match std::fs::metadata(path) {
                Ok(m) => m.len(),
                Err(_) => return false,
            };
            if size1 == 0 {
                std::thread::sleep(Duration::from_millis(500));
                continue;
            }
            std::thread::sleep(Duration::from_millis(500));
            let size2 = match std::fs::metadata(path) {
                Ok(m) => m.len(),
                Err(_) => return false,
            };
            if size1 == size2 {
                return true;
            }
        }
        std::thread::sleep(Duration::from_millis(500));
    }
    false
}

fn process_new_file(
    client: &api::BallchasingClient,
    path: &PathBuf,
    visibility: &str,
    state: &Arc<Mutex<UploaderState>>,
    config_path: &PathBuf,
) {
    let file_name = path
        .file_name()
        .unwrap_or_default()
        .to_string_lossy()
        .to_string();

    if !wait_for_file_stable(path) {
        let size = std::fs::metadata(path).map(|m| m.len()).unwrap_or(0);
        let mut s = state.lock().unwrap_or_else(|p| p.into_inner());
        s.update_log(
            &file_name,
            UploadLogStatus::Failed(format!("File not ready after 12s (size: {} bytes)", size)),
        );
        return;
    }

    let hash = match upload_queue::hash_file(path) {
        Ok(h) => h,
        Err(e) => {
            let mut s = state.lock().unwrap_or_else(|p| p.into_inner());
            s.update_log(
                &file_name,
                UploadLogStatus::Failed(format!("Hash error: {}", e)),
            );
            return;
        }
    };

    {
        let s = state.lock().unwrap_or_else(|p| p.into_inner());
        if s.config.is_uploaded(&hash) {
            return;
        }
    }

    let file_size = std::fs::metadata(path).map(|m| m.len()).unwrap_or(0);
    {
        let mut s = state.lock().unwrap_or_else(|p| p.into_inner());
        s.add_log(UploadLogEntry {
            file_name: file_name.clone(),
            status: UploadLogStatus::Uploading,
            time: format!(
                "{} ({}KB)",
                chrono::Local::now().format("%H:%M:%S"),
                file_size / 1024
            ),
        });
    }

    match client.upload_replay(path, visibility) {
        Ok(resp) => {
            let mut s = state.lock().unwrap_or_else(|p| p.into_inner());
            s.config.mark_uploaded(hash);
            let _ = s.config.save(config_path);
            s.update_log(&file_name, UploadLogStatus::Success(resp.id));
        }
        Err(e) => {
            let msg = format!("{}", e);
            let mut s = state.lock().unwrap_or_else(|p| p.into_inner());
            if msg.contains("Duplicate") {
                s.config.mark_uploaded(hash);
                let _ = s.config.save(config_path);
                s.update_log(&file_name, UploadLogStatus::Duplicate);
            } else {
                s.update_log(&file_name, UploadLogStatus::Failed(msg));
            }
        }
    }
}
