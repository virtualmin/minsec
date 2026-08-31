//! JSON request/response bodies, field-for-field with `pkg/wire` in the
//! minsec.io repo.

use serde::{Deserialize, Serialize};

/// One reported automatic ban. `ip` is a CIDR string: IPv4 `/24`–`/32`,
/// IPv6 `/48`–`/64`. Manual bans and unbans are never reported.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Report {
    pub ts: i64,
    pub ip: String,
    pub filter: String,
    pub count: i64,
    pub ban_ttl: i64,
    /// Repeat-offender depth from the daemon's escalation ladder: 0 on a
    /// first ban, incrementing each time the address is re-banned inside
    /// the escalation memory.
    pub escalation: u32,
}

/// Body of `POST /v1/reports`. `seq` must strictly increase per agent.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportBatch {
    pub seq: u64,
    pub agent_version: String,
    pub reports: Vec<Report>,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct ReportResponse {
    #[serde(default)]
    pub accepted: u64,
    #[serde(default)]
    pub rejected: u64,
    #[serde(default)]
    pub duplicate: bool,
}

/// Response of `POST /v1/enroll/challenge`.
#[derive(Debug, Clone, Deserialize)]
pub struct Challenge {
    pub challenge: String,
    pub difficulty: u32,
    pub expires_in: u64,
    pub algo: String,
}

pub const POW_ALGO: &str = "sha256-pow-v1";

/// Body of `POST /v1/enroll`.
#[derive(Debug, Clone, Serialize)]
pub struct EnrollRequest {
    pub challenge: String,
    pub pow_nonce: String,
    /// base64 (std) 32-byte Ed25519 public key.
    pub pubkey: String,
    pub agent_version: String,
    /// Reserved for Virtualmin licensing; always null in v1.
    pub install_token: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct EnrollResponse {
    pub host_id: String,
    pub report_url: String,
    pub feed_url: String,
    /// Minimum seconds between report submissions.
    pub min_report_interval: u64,
}

/// Error body used by every non-2xx JSON response.
#[derive(Debug, Clone, Deserialize)]
pub struct ErrorResponse {
    pub error: String,
    #[serde(default)]
    pub message: String,
}
