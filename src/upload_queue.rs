use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

const MAX_RETRIES: u32 = 5;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingUpload {
    pub replay_path: String,
    pub file_hash: String,
    pub retries: u32,
    pub created_at: String,
}

pub struct UploadQueue {
    queue_path: PathBuf,
    jobs: Vec<PendingUpload>,
}

impl UploadQueue {
    pub fn load(queue_path: impl Into<PathBuf>) -> Self {
        let queue_path = queue_path.into();
        let jobs = if queue_path.exists() {
            match std::fs::read_to_string(&queue_path) {
                Ok(data) => serde_json::from_str(&data).unwrap_or_default(),
                Err(_) => Vec::new(),
            }
        } else {
            Vec::new()
        };
        Self { queue_path, jobs }
    }

    pub fn enqueue(&mut self, job: PendingUpload) {
        self.jobs.push(job);
        self.save();
    }
    pub fn complete(&mut self, index: usize) {
        if index < self.jobs.len() {
            self.jobs.remove(index);
            self.save();
        }
    }

    pub fn pending(&self) -> &[PendingUpload] {
        &self.jobs
    }
    pub fn increment_retry(&mut self, index: usize) {
        if let Some(job) = self.jobs.get_mut(index) {
            job.retries += 1;
            self.save();
        }
    }

    pub fn is_expired(job: &PendingUpload) -> bool {
        job.retries >= MAX_RETRIES
    }
    pub fn prune_expired(&mut self) -> usize {
        let before = self.jobs.len();
        self.jobs.retain(|j| j.retries < MAX_RETRIES);
        let removed = before - self.jobs.len();
        if removed > 0 {
            self.save();
        }
        removed
    }

    fn save(&self) {
        if let Ok(data) = serde_json::to_string_pretty(&self.jobs) {
            if let Some(parent) = self.queue_path.parent() {
                let _ = std::fs::create_dir_all(parent);
            }
            let tmp = self.queue_path.with_extension("tmp");
            if std::fs::write(&tmp, &data).is_ok() {
                let _ = std::fs::rename(&tmp, &self.queue_path);
            }
        }
    }
}

pub fn hash_file(path: &std::path::Path) -> Result<String> {
    use sha2::{Digest, Sha256};
    let data = std::fs::read(path)?;
    let hash = Sha256::digest(&data);
    Ok(format!("{:x}", hash))
}
