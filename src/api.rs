use anyhow::Result;
use reqwest::multipart;
use serde::Deserialize;
use std::path::Path;

const BASE_URL: &str = "https://ballchasing.com/api";

#[derive(Debug, Deserialize)]
pub struct PingResponse {
    pub name: String,
    pub steam_id: Option<String>,
    #[serde(rename = "type")]
    pub account_type: String,
}

#[derive(Debug, Deserialize)]
pub struct UploadResponse {
    pub id: String,
    pub location: String,
}

#[derive(Debug)]
pub enum UploadError {
    Duplicate,
    RateLimited,
    ApiError(String),
    Network(reqwest::Error),
}

impl std::fmt::Display for UploadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Duplicate => write!(f, "Duplicate replay (already uploaded)"),
            Self::RateLimited => write!(f, "Rate limited (try again later)"),
            Self::ApiError(msg) => write!(f, "API error: {}", msg),
            Self::Network(e) => write!(f, "Network error: {}", e),
        }
    }
}

impl std::error::Error for UploadError {}

pub struct BallchasingClient {
    client: reqwest::Client,
    api_key: String,
}

impl BallchasingClient {
    pub fn new(api_key: &str) -> Self {
        Self {
            client: reqwest::Client::new(),
            api_key: api_key.to_string(),
        }
    }

    pub async fn ping(&self) -> Result<PingResponse> {
        let resp = self
            .client
            .get(BASE_URL)
            .header("Authorization", &self.api_key)
            .send()
            .await?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            anyhow::bail!("Ping failed ({}): {}", status, body);
        }

        Ok(resp.json().await?)
    }

    pub async fn upload_replay(
        &self,
        path: &Path,
        visibility: &str,
    ) -> std::result::Result<UploadResponse, UploadError> {
        let file_name = path
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .to_string();
        let file_bytes = std::fs::read(path).map_err(|e| {
            UploadError::ApiError(format!("Failed to read file: {}", e))
        })?;

        let part = multipart::Part::bytes(file_bytes)
            .file_name(file_name)
            .mime_str("application/octet-stream")
            .map_err(|e| UploadError::ApiError(format!("MIME error: {}", e)))?;

        let form = multipart::Form::new().part("file", part);

        let url = format!("{}/v2/upload?visibility={}", BASE_URL, visibility);

        let resp = self
            .client
            .post(&url)
            .header("Authorization", &self.api_key)
            .multipart(form)
            .send()
            .await
            .map_err(UploadError::Network)?;

        let status = resp.status();

        if status.as_u16() == 409 {
            return Err(UploadError::Duplicate);
        }
        if status.as_u16() == 429 {
            return Err(UploadError::RateLimited);
        }
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(UploadError::ApiError(format!("({}): {}", status, body)));
        }

        resp.json()
            .await
            .map_err(|e| UploadError::ApiError(format!("Parse error: {}", e)))
    }
}
