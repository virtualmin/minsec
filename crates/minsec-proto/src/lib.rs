//! The minsec multiplayer wire protocol, mirroring the backend's `pkg/wire`
//! Go package. The two implementations are held together by the shared
//! signing vectors in `testdata/vectors.json` (source of truth:
//! `pkg/wire/testdata/vectors.json` in the minsec.io repo); any change to the
//! canonical construction must update both repos and the vectors.

pub mod feed;
pub mod pow;
pub mod sign;
pub mod types;

pub const HEADER_HOST: &str = "X-Minsec-Host";
pub const HEADER_TIMESTAMP: &str = "X-Minsec-Timestamp";
pub const HEADER_SIGNATURE: &str = "X-Minsec-Signature";

/// Batch limits enforced by the server (`POST /v1/reports`).
pub const MAX_BATCH_ITEMS: usize = 1000;
pub const MAX_BODY_BYTES: usize = 1 << 20;

pub(crate) fn hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0xf) as usize] as char);
    }
    s
}
