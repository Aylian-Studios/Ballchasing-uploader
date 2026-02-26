use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
#[derive(Default)]
pub enum Visibility {
    Public,
    Unlisted,
    #[default]
    Private,
}

impl Visibility {
    pub fn as_str(&self) -> &str {
        match self {
            Self::Public => "public",
            Self::Unlisted => "unlisted",
            Self::Private => "private",
        }
    }
}

impl std::str::FromStr for Visibility {
    type Err = anyhow::Error;
    fn from_str(s: &str) -> Result<Self> {
        match s.to_lowercase().as_str() {
            "public" => Ok(Self::Public),
            "unlisted" => Ok(Self::Unlisted),
            "private" => Ok(Self::Private),
            _ => anyhow::bail!(
                "Invalid visibility: '{}'. Use public, unlisted, or private.",
                s
            ),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UploaderConfig {
    pub api_key: String,

    // Legacy single directory support (will be migrated to watch_dirs if present)
    pub watch_dir: Option<PathBuf>,
    #[serde(default = "default_watch_dirs")]
    pub watch_dirs: Vec<PathBuf>,

    pub visibility: Visibility,
    #[serde(default)]
    pub uploaded_hashes: Vec<String>,

    // BakkesMod style settings
    #[serde(default)]
    pub enable_safe_mode: bool,
    #[serde(default)]
    pub run_on_startup: bool,
    #[serde(default)]
    pub hide_when_minimized: bool,
    #[serde(default)]
    pub minimize_on_start: bool,
    #[serde(default)]
    pub disable_warnings: bool,
}

pub fn default_watch_dirs() -> Vec<PathBuf> {
    vec![default_replay_dir()]
}

impl Default for UploaderConfig {
    fn default() -> Self {
        Self {
            api_key: String::new(),
            watch_dir: None,
            watch_dirs: default_watch_dirs(),
            visibility: Visibility::default(),
            uploaded_hashes: Vec::new(),
            enable_safe_mode: false,
            run_on_startup: false,
            hide_when_minimized: false,
            minimize_on_start: false,
            disable_warnings: false,
        }
    }
}

impl UploaderConfig {
    pub fn load(path: &PathBuf) -> Self {
        if path.exists() {
            match std::fs::read_to_string(path) {
                Ok(data) => match serde_json::from_str::<UploaderConfig>(&data) {
                    Ok(mut config) => {
                        // Migrate legacy watch_dir to watch_dirs
                        if let Some(dir) = config.watch_dir.take() {
                            if !config.watch_dirs.contains(&dir) {
                                config.watch_dirs.push(dir);
                            }
                            // Save immediately to clear the legacy field
                            let _ = config.save(path);
                        }
                        return config;
                    }
                    Err(e) => eprintln!("Warning: config parse error: {}", e),
                },
                Err(e) => eprintln!("Warning: config read error: {}", e),
            }
        }
        Self::default()
    }

    pub fn save(&self, path: &PathBuf) -> Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let data = serde_json::to_string_pretty(self)?;
        let tmp = path.with_extension("tmp");
        std::fs::write(&tmp, &data)?;
        std::fs::rename(&tmp, path)?;
        Ok(())
    }

    pub fn is_uploaded(&self, hash: &str) -> bool {
        self.uploaded_hashes.iter().any(|h| h == hash)
    }
    pub fn mark_uploaded(&mut self, hash: String) {
        if !self.is_uploaded(&hash) {
            self.uploaded_hashes.push(hash);
        }
    }
}

pub fn default_config_path() -> PathBuf {
    dirs::config_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("ballchasing-uploader")
        .join("config.json")
}

pub fn default_replay_dir() -> PathBuf {
    if cfg!(target_os = "windows") {
        dirs::document_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join("My Games")
            .join("Rocket League")
            .join("TAGame")
            .join("Demos")
    } else {
        dirs::home_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join(".local")
            .join("share")
            .join("Rocket League")
            .join("TAGame")
            .join("Demos")
    }
}
