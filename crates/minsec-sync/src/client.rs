//! Thin HTTP client for the minsec.io API. Non-2xx responses become
//! `ApiError` with the server's error code, so callers can react to
//! specific codes (`already_enrolled`, `quota_exceeded`, …).

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use ed25519_dalek::SigningKey;
use minsec_proto::types;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

pub struct Api {
    agent: ureq::Agent,
    server: String,
}

#[derive(Debug)]
pub struct ApiError {
    pub status: u16,
    pub code: String,
    pub message: String,
    pub retry_after: Option<u64>,
}

impl std::fmt::Display for ApiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "server said {} ({})", self.code, self.status)?;
        if !self.message.is_empty() {
            write!(f, ": {}", self.message)?;
        }
        if let Some(s) = self.retry_after {
            write!(f, " [retry after {s}s]")?;
        }
        Ok(())
    }
}

impl std::error::Error for ApiError {}

/// A feed fetch outcome.
pub enum FeedFetch {
    NotModified,
    Body { text: String, etag: String },
}

pub fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

impl Api {
    pub fn new(server: &str) -> Self {
        let config = ureq::Agent::config_builder()
            .http_status_as_error(false)
            .timeout_global(Some(Duration::from_secs(120)))
            .user_agent(concat!("minsec-sync/", env!("CARGO_PKG_VERSION")))
            .build();
        Self {
            agent: config.into(),
            server: server.trim_end_matches('/').to_string(),
        }
    }

    fn url(&self, path: &str) -> String {
        format!("{}{path}", self.server)
    }

    fn error_from(status: u16, retry_after: Option<u64>, body: &str) -> ApiError {
        let parsed: Option<types::ErrorResponse> = serde_json::from_str(body).ok();
        match parsed {
            Some(e) => ApiError {
                status,
                code: e.error,
                message: e.message,
                retry_after,
            },
            None => ApiError {
                status,
                code: format!("http_{status}"),
                message: body.chars().take(200).collect(),
                retry_after,
            },
        }
    }

    fn read_ok(resp: &mut ureq::http::Response<ureq::Body>) -> Result<String, ApiError> {
        let status = resp.status().as_u16();
        let retry_after = resp
            .headers()
            .get("Retry-After")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse().ok());
        let body = resp.body_mut().read_to_string().unwrap_or_default();
        if !(200..300).contains(&status) {
            return Err(Self::error_from(status, retry_after, &body));
        }
        Ok(body)
    }

    pub fn challenge(&self) -> anyhow::Result<types::Challenge> {
        let mut resp = self
            .agent
            .post(self.url("/v1/enroll/challenge"))
            .header("Content-Type", "application/json")
            .send("{}")?;
        let body = Self::read_ok(&mut resp)?;
        let ch: types::Challenge = serde_json::from_str(&body)?;
        if ch.algo != types::POW_ALGO {
            anyhow::bail!("server wants unknown PoW algorithm {:?}; upgrade minsec-sync", ch.algo);
        }
        Ok(ch)
    }

    pub fn enroll(&self, req: &types::EnrollRequest) -> Result<types::EnrollResponse, ApiError> {
        let mut resp = self
            .agent
            .post(self.url("/v1/enroll"))
            .header("Content-Type", "application/json")
            .send(serde_json::to_string(req).expect("serializable"))
            .map_err(|e| ApiError {
                status: 0,
                code: "transport".into(),
                message: e.to_string(),
                retry_after: None,
            })?;
        let body = Self::read_ok(&mut resp)?;
        serde_json::from_str(&body).map_err(|e| ApiError {
            status: resp.status().as_u16(),
            code: "bad_response".into(),
            message: e.to_string(),
            retry_after: None,
        })
    }

    /// Submit one signed report batch. The signature covers the exact bytes
    /// sent, so the batch is serialized here, once.
    pub fn submit(
        &self,
        key: &SigningKey,
        host_id: &str,
        batch: &types::ReportBatch,
    ) -> anyhow::Result<types::ReportResponse> {
        let body = serde_json::to_vec(batch)?;
        let ts = now_unix() as i64;
        let sig = minsec_proto::sign::sign(key, host_id, ts, &body);
        let mut resp = self
            .agent
            .post(self.url("/v1/reports"))
            .header("Content-Type", "application/json")
            .header(minsec_proto::HEADER_HOST, host_id)
            .header(minsec_proto::HEADER_TIMESTAMP, ts.to_string())
            .header(minsec_proto::HEADER_SIGNATURE, B64.encode(sig))
            .send(&body[..])?;
        let body = Self::read_ok(&mut resp)?;
        Ok(serde_json::from_str(&body)?)
    }

    pub fn pull_feed(&self, tier: &str, family: &str, etag: &str, since: i64) -> anyhow::Result<FeedFetch> {
        let mut url = self.url(&format!("/v1/feed/{tier}/{family}"));
        if since > 0 {
            url.push_str(&format!("?since={since}"));
        }
        let mut req = self.agent.get(url);
        if !etag.is_empty() {
            req = req.header("If-None-Match", etag);
        }
        let mut resp = req.call()?;
        if resp.status().as_u16() == 304 {
            return Ok(FeedFetch::NotModified);
        }
        let new_etag = resp
            .headers()
            .get("ETag")
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default()
            .to_string();
        let text = Self::read_ok(&mut resp)?;
        Ok(FeedFetch::Body { text, etag: new_etag })
    }
}
