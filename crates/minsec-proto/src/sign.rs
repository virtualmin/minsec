//! Detached Ed25519 request signing for `POST /v1/reports`.
//!
//! The signature covers the canonical string (newline-separated, no
//! trailing newline):
//!
//! ```text
//! minsec-report-v1
//! <host_id>
//! <timestamp>
//! <hex(sha256(request body bytes))>
//! ```
//!
//! The digest is over the exact body bytes sent — there is no JSON
//! canonicalization anywhere in the protocol.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};

pub const CANONICAL_PREFIX: &str = "minsec-report-v1";

pub fn canonical_string(host_id: &str, timestamp: i64, body: &[u8]) -> String {
    let digest = Sha256::digest(body);
    format!("{CANONICAL_PREFIX}\n{host_id}\n{timestamp}\n{}", crate::hex(&digest))
}

/// Sign a request; the result goes base64 (std) into `X-Minsec-Signature`.
pub fn sign(key: &SigningKey, host_id: &str, timestamp: i64, body: &[u8]) -> [u8; 64] {
    key.sign(canonical_string(host_id, timestamp, body).as_bytes())
        .to_bytes()
}

pub fn verify(key: &VerifyingKey, host_id: &str, timestamp: i64, body: &[u8], signature: &[u8; 64]) -> bool {
    let sig = Signature::from_bytes(signature);
    key.verify(canonical_string(host_id, timestamp, body).as_bytes(), &sig)
        .is_ok()
}
