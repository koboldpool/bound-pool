//! Helpers shared by the pool and the miner (hex, time, targets, work). From neb-pool's common.rs,
//! plus BOUND's 256-bit target helpers.

use std::time::{SystemTime, UNIX_EPOCH};

pub fn hex(b: &[u8]) -> String {
    let mut s = String::with_capacity(b.len() * 2);
    for x in b {
        s.push_str(&format!("{x:02x}"));
    }
    s
}

pub fn unhex(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(s.get(i..i + 2)?, 16).ok()).collect()
}

pub fn unhex32(s: &str) -> Option<[u8; 32]> {
    unhex(s)?.try_into().ok()
}

/// A 256-bit number from its display hex (most significant byte first, as the node's to_hex()
/// shows hashes and targets) into BOUND's byte order (least significant first).
pub fn from_display(s: &str) -> Option<[u8; 32]> {
    let mut b = unhex32(s)?;
    b.reverse();
    Some(b)
}

/// The inverse of from_display.
pub fn to_display(b: &[u8; 32]) -> String {
    let mut r = *b;
    r.reverse();
    hex(&r)
}

pub fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

/// A 256-bit little-endian value as a float (enough precision for accounting and hash rates).
pub fn le_to_f64(v: &[u8; 32]) -> f64 {
    v.iter().rev().fold(0.0, |acc, &b| acc * 256.0 + b as f64)
}

/// Expected hashes for one hash at or below `target`: 2^256 / (target + 1).
pub fn work_of(target: &[u8; 32]) -> f64 {
    2f64.powi(256) / (le_to_f64(target) + 1.0)
}

/// hash <= target, both little-endian 256-bit numbers (BOUND's check_proof_of_work).
pub fn meets(hash: &[u8; 32], target: &[u8; 32]) -> bool {
    for i in (0..32).rev() {
        if hash[i] != target[i] {
            return hash[i] < target[i];
        }
    }
    true
}

/// The target 2^(256-k) - 1: a hash meets it once in 2^k tries on average.
pub fn target_of_k(k: u32) -> [u8; 32] {
    let mut t = [0u8; 32];
    let bits = 256u32.saturating_sub(k.min(256));
    for i in 0..bits as usize {
        t[i / 8] |= 1 << (i % 8);
    }
    t
}

/// The easier (larger) of two targets.
pub fn easier(a: [u8; 32], b: [u8; 32]) -> [u8; 32] {
    if meets(&a, &b) { b } else { a }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn targets() {
        assert_eq!(target_of_k(0), [0xff; 32]);
        let t = target_of_k(16);
        assert_eq!(to_display(&t), format!("0000{}", "f".repeat(60)));
        assert!((work_of(&t) - 65536.0).abs() < 1e-6);
        assert!(meets(&[0u8; 32], &t));
        assert!(!meets(&[0xff; 32], &t));
        assert!(meets(&t, &t));
        assert_eq!(easier(target_of_k(10), target_of_k(12)), target_of_k(10));
        assert_eq!(from_display(&to_display(&t)).unwrap(), t);
    }
}
