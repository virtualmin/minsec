//! Enrollment proof of work (`sha256-pow-v1`): find an ASCII nonce such
//! that `sha256(challenge || nonce)` has at least `difficulty` leading zero
//! bits.

use sha2::{Digest, Sha256};

pub fn leading_zero_bits(digest: &[u8]) -> u32 {
    let mut bits = 0;
    for b in digest {
        if *b == 0 {
            bits += 8;
        } else {
            bits += b.leading_zeros();
            break;
        }
    }
    bits
}

pub fn check(challenge: &str, nonce: &str, difficulty: u32) -> bool {
    let mut h = Sha256::new();
    h.update(challenge.as_bytes());
    h.update(nonce.as_bytes());
    leading_zero_bits(&h.finalize()) >= difficulty
}

/// Brute-force a nonce. Difficulty 20 is roughly 1–5 seconds of one core.
pub fn solve(challenge: &str, difficulty: u32) -> String {
    for i in 0u64.. {
        let nonce = i.to_string();
        if check(challenge, &nonce, difficulty) {
            return nonce;
        }
    }
    unreachable!("u64 nonce space exhausted")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zero_bits() {
        assert_eq!(leading_zero_bits(&[0xff]), 0);
        assert_eq!(leading_zero_bits(&[0x0f]), 4);
        assert_eq!(leading_zero_bits(&[0x00, 0x80]), 8);
        assert_eq!(leading_zero_bits(&[0x00, 0x00]), 16);
    }

    #[test]
    fn solve_and_check() {
        let nonce = solve("test-challenge", 12);
        assert!(check("test-challenge", &nonce, 12));
        assert!(!check("test-challenge", &nonce, 200));
    }
}
