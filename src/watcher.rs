use anyhow::Result;
use notify_debouncer_mini::{new_debouncer, DebouncedEventKind};
use std::path::PathBuf;
use std::sync::mpsc;
use std::time::Duration;

pub fn watch_directories(dirs: &[PathBuf]) -> Result<mpsc::Receiver<PathBuf>> {
    let (tx, rx) = mpsc::channel();

    let valid_dirs: Vec<PathBuf> = dirs.iter().filter(|d| d.exists()).cloned().collect();
    if valid_dirs.is_empty() {
        anyhow::bail!("None of the watch directories exist");
    }

    std::thread::spawn(move || {
        let (notify_tx, notify_rx) = std::sync::mpsc::channel();

        let mut debouncer = match new_debouncer(Duration::from_millis(500), notify_tx) {
            Ok(d) => d,
            Err(e) => {
                eprintln!("Failed to create file watcher: {}", e);
                return;
            }
        };

        for dir in &valid_dirs {
            if let Err(e) = debouncer
                .watcher()
                .watch(dir, notify::RecursiveMode::NonRecursive)
            {
                eprintln!("Failed to watch directory {:?}: {}", dir, e);
            } else {
                println!("Watching {:?} for new replays...", dir);
            }
        }

        while let Ok(Ok(events)) = notify_rx.recv() {
            for event in events {
                if event.kind == DebouncedEventKind::Any {
                    let path = event.path;
                    if path.extension().is_some_and(|ext| ext == "replay") && path.exists() {
                        println!(
                            "New replay detected: {:?}",
                            path.file_name().unwrap_or_default()
                        );
                        let _ = tx.send(path);
                    }
                }
            }
        }
    });

    Ok(rx)
}
