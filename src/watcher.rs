use anyhow::Result;
use notify_debouncer_mini::{new_debouncer, DebouncedEventKind};
use std::path::PathBuf;
use std::sync::mpsc;
use std::time::Duration;

pub fn watch_directory(dir: &PathBuf) -> Result<mpsc::Receiver<PathBuf>> {
    let (tx, rx) = mpsc::channel();
    let dir = dir.clone();

    if !dir.exists() {
        anyhow::bail!("Watch directory does not exist: {:?}", dir);
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

        if let Err(e) = debouncer
            .watcher()
            .watch(&dir, notify::RecursiveMode::NonRecursive)
        {
            eprintln!("Failed to watch directory {:?}: {}", dir, e);
            return;
        }

        println!("Watching {:?} for new replays...", dir);

        loop {
            match notify_rx.recv() {
                Ok(Ok(events)) => {
                    for event in events {
                        if event.kind == DebouncedEventKind::Any {
                            let path = event.path;
                            if path.extension().map_or(false, |ext| ext == "replay")
                                && path.exists()
                            {
                                println!("New replay detected: {:?}", path.file_name().unwrap_or_default());
                                let _ = tx.send(path);
                            }
                        }
                    }
                }
                Ok(Err(errors)) => {
                    eprintln!("Watch error: {:?}", errors);
                }
                Err(_) => break, // Channel closed
            }
        }
    });

    Ok(rx)
}
