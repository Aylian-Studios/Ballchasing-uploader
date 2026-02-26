use anyhow::Result;
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

impl From<reqwest::Error> for UploadError {
    fn from(err: reqwest::Error) -> Self {
        UploadError::Network(err)
    }
}

impl From<std::io::Error> for UploadError {
    fn from(err: std::io::Error) -> Self {
        UploadError::ApiError(format!("IO error: {}", err))
    }
}

#[derive(Debug)]
pub struct BallchasingClient {
    client: reqwest::blocking::Client,
    api_key: String,
}

impl BallchasingClient {
    pub fn new(api_key: &str) -> Self {
        let client = reqwest::blocking::Client::builder()
            .timeout(std::time::Duration::from_secs(60))
            .http1_only()
            .build()
            .unwrap_or_else(|_| reqwest::blocking::Client::new());

        Self {
            client,
            api_key: api_key.to_string(),
        }
    }

    pub fn ping(&self) -> Result<PingResponse> {
        let resp = self
            .client
            .get(BASE_URL)
            .header("Authorization", &self.api_key)
            .send()?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().unwrap_or_default();
            anyhow::bail!("Ping failed ({}): {}", status, body);
        }

        Ok(resp.json()?)
    }

    pub fn upload_replay(
        &self,
        path: &Path,
        visibility: &str,
    ) -> std::result::Result<UploadResponse, UploadError> {
        std::thread::sleep(std::time::Duration::from_secs(2));

        let form = reqwest::blocking::multipart::Form::new().file("file", path)?;

        let url = format!("{}/v2/upload?visibility={}", BASE_URL, visibility);
        eprintln!("[upload] POST {}", url);

        let resp = self
            .client
            .post(&url)
            .header("Authorization", &self.api_key)
            .multipart(form)
            .send()?;

        let status = resp.status();
        eprintln!("[upload] response status={}", status);

        if status.as_u16() == 409 {
            return Err(UploadError::Duplicate);
        }
        if status.as_u16() == 429 {
            return Err(UploadError::RateLimited);
        }
        if !status.is_success() {
            let body = resp.text().unwrap_or_default();
            eprintln!("[upload] error body: {}", body);
            return Err(UploadError::ApiError(format!("({}): {}", status, body)));
        }

        Ok(resp.json()?)
    }
}
