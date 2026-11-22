//! The second stratum dialect: Bitcoin stratum v1 as Miningcore-family BOUND pools speak it, for GPU miners
//! like BoundCuda (Crypto Connection, MIT). Pure functions only; the pool's sessions are in main.rs.
//!
//!   -> mining.subscribe ["BoundCuda/x"]           <- [[["mining.set_difficulty", id], ["mining.notify", id]], extraNonce1, 4]
//!   -> mining.authorize ["ADDRESS.worker", "x"]   <- true
//!   <- mining.set_difficulty [d]                  share target = PowLimit (0x1e03ffff) / d
//!   <- mining.notify [job, prevhash, coinb1, coinb2, [branches], version, nbits, ntime, clean]
//!   -> mining.submit ["ADDRESS.worker", job, extraNonce2, ntime, nonce]   (8 hex digits each)
//!
//! Coinbase = coinb1 || extraNonce1 || extraNonce2 || coinb2. Here the extra nonces end the coinbase memo
//! (pool tag || en1 || en2), the memo being the transaction's last field, so coinb2 is empty. Merkle root:
//! h = tagged("BOUND/wtxid", coinbase), then h = tagged("BOUND/merkle", h || branch) for each branch. prevhash is
//! the header's raw parent bytes with each 4-byte word reversed; version, nbits and ntime are big-endian hex of the
//! header's little-endian numbers; the nonce is the big-endian hex of the u32 stored little-endian at bytes 76..80.

use crate::boundhash::tagged_hash;
use crate::chain::{compact_size, wtxid};
use crate::common::{hex, unhex};

/// What a notify carries, built once per template and shared by every session of this dialect.
#[derive(Clone, Debug, PartialEq)]
pub struct McWork {
    pub coinb1: Vec<u8>,
    pub branches: Vec<[u8; 32]>,
    /// prevhash as sent: the raw parent bytes, each 4-byte word reversed.
    pub prevhash: [u8; 32],
    pub version: u32,
    pub bits: u32,
    pub ntime: u32,
}

/// Bytes of the extra nonces in the coinbase.
pub const EN1_SIZE: usize = 4;
pub const EN2_SIZE: usize = 4;

/// The merkle branch of leaf 0 (the coinbase) in BOUND's tree (odd last node promoted, not duplicated):
/// the sibling of the coinbase's ancestor on every level below the root. `others` are the other txs' wtxids.
pub fn coinbase_branch(others: &[[u8; 32]]) -> Vec<[u8; 32]> {
    let mut branch = Vec::new();
    // The level without its first node (which depends on the coinbase).
    let mut rest: Vec<[u8; 32]> = others.to_vec();
    while !rest.is_empty() {
        branch.push(rest[0]);
        // Next level: node 0 = pair(coinbase side, rest[0]); nodes 1.. pair up rest[1..] in twos.
        let mut next = Vec::new();
        let tail = &rest[1..];
        for pair in tail.chunks(2) {
            if pair.len() == 2 {
                let mut buf = [0u8; 64];
                buf[..32].copy_from_slice(&pair[0]);
                buf[32..].copy_from_slice(&pair[1]);
                next.push(tagged_hash("BOUND/merkle", &buf));
            } else {
                next.push(pair[0]);
            }
        }
        rest = next;
    }
    branch
}

/// The root from the coinbase's wtxid and its branch (BoundCuda's build_header).
pub fn root_from_branch(coinbase: &[u8], branches: &[[u8; 32]]) -> [u8; 32] {
    let mut h = wtxid(coinbase);
    for b in branches {
        let mut buf = [0u8; 64];
        buf[..32].copy_from_slice(&h);
        buf[32..].copy_from_slice(b);
        h = tagged_hash("BOUND/merkle", &buf);
    }
    h
}

/// Each 4-byte word reversed (prevhash both ways).
pub fn swap_words(b: &[u8; 32]) -> [u8; 32] {
    let mut out = [0u8; 32];
    for i in (0..32).step_by(4) {
        for k in 0..4 {
            out[i + k] = b[i + 3 - k];
        }
    }
    out
}

/// The shared job: coinb1 = the template's coinbase up to its memo, the memo's length (tag + en1 + en2) and the
/// tag. `header` is the template's header (version, parent, time, bits); `others` the other txs' wtxids.
pub fn build_work(coinbase_prefix: &[u8], tag: &[u8], header: &[u8; 80], others: &[[u8; 32]]) -> McWork {
    let mut coinb1 = coinbase_prefix.to_vec();
    compact_size((tag.len() + EN1_SIZE + EN2_SIZE) as u64, &mut coinb1);
    coinb1.extend_from_slice(tag);
    let le = |i: usize| u32::from_le_bytes(header[i..i + 4].try_into().unwrap());
    McWork {
        coinb1,
        branches: coinbase_branch(others),
        prevhash: swap_words(header[4..36].try_into().unwrap()),
        version: le(0),
        bits: le(72),
        ntime: le(68),
    }
}

/// The coinbase a submit stands for.
pub fn coinbase(work: &McWork, en1: &[u8], en2: &[u8]) -> Vec<u8> {
    let mut cb = work.coinb1.clone();
    cb.extend_from_slice(en1);
    cb.extend_from_slice(en2);
    cb
}

/// The 80-byte header a submit stands for (the pool's side of BoundCuda's build_header + nonce).
pub fn header(work: &McWork, en1: &[u8], en2: &[u8], ntime: u32, nonce: u32) -> [u8; 80] {
    let mut h = [0u8; 80];
    h[0..4].copy_from_slice(&work.version.to_le_bytes());
    h[4..36].copy_from_slice(&swap_words(&work.prevhash));
    h[36..68].copy_from_slice(&root_from_branch(&coinbase(work, en1, en2), &work.branches));
    h[68..72].copy_from_slice(&ntime.to_le_bytes());
    h[72..76].copy_from_slice(&work.bits.to_le_bytes());
    h[76..80].copy_from_slice(&nonce.to_le_bytes());
    h
}

/// The notify params (clean flag last).
pub fn notify_params(job_id: &str, work: &McWork, clean: bool) -> serde_json::Value {
    serde_json::json!([
        job_id,
        hex(&work.prevhash),
        hex(&work.coinb1),
        "",
        work.branches.iter().map(|b| hex(b)).collect::<Vec<_>>(),
        format!("{:08x}", work.version),
        format!("{:08x}", work.bits),
        format!("{:08x}", work.ntime),
        clean
    ])
}

/// 8 hex digits as a big-endian u32 (nonce, ntime), as BoundCuda sends them ("%08x").
pub fn parse_hex32(s: &str) -> Option<u32> {
    (s.len() == 8).then(|| u32::from_str_radix(s, 16).ok()).flatten()
}

/// extraNonce2: 8 hex digits = its 4 coinbase bytes in that order.
pub fn parse_en2(s: &str) -> Option<[u8; 4]> {
    unhex(s)?.try_into().ok()
}

/// The share target (little-endian) for difficulty d, computed exactly as BoundCuda's target_from_diff:
/// (PowLimit << 16) / floor(d * 65536), the divisor clamped to 1 ..= 2^32 - 1, PowLimit = 0x03ffff * 256^27.
pub fn target_from_diff(d: f64) -> [u8; 32] {
    let mut limb = [0u32; 8];
    limb[7] = 0x3ffff << 8;
    let dd = (d * 65536.0).clamp(1.0, 4294967295.0);
    let div = dd as u64;
    let mut rem = 0u64;
    for i in (0..8).rev() {
        let cur = (rem << 32) | limb[i] as u64;
        limb[i] = (cur / div) as u32;
        rem = cur % div;
    }
    let mut t = [0u8; 32];
    for i in 0..8 {
        t[4 * i..4 * i + 4].copy_from_slice(&limb[i].to_le_bytes());
    }
    t
}

/// Difficulty for about 2^k hashes per share: 2^(k-22) (PowLimit ≈ 2^22 hashes). Exact for k in 6..=37,
/// where floor(d * 65536) is a power of two inside BoundCuda's divisor range.
pub const K_MIN: u32 = 6;
pub const K_MAX: u32 = 37;

pub fn diff_of_k(k: u32) -> f64 {
    2f64.powi(k.clamp(K_MIN, K_MAX) as i32 - 22)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain::merkle_root;
    use crate::common::{meets, work_of};

    #[test]
    fn branch_matches_the_full_tree() {
        for n in 0..12usize {
            let others: Vec<[u8; 32]> = (0..n).map(|i| [i as u8 + 1; 32]).collect();
            let cb = b"coinbase".to_vec();
            let mut leaves = vec![wtxid(&cb)];
            leaves.extend_from_slice(&others);
            assert_eq!(root_from_branch(&cb, &coinbase_branch(&others)), merkle_root(&leaves), "{n} other txs");
        }
    }

    #[test]
    fn targets_follow_boundcuda() {
        // d = 1: PowLimit itself (0x1e03ffff).
        let mut pl = [0u8; 32];
        pl[27] = 0xff;
        pl[28] = 0xff;
        pl[29] = 0x03;
        assert_eq!(target_from_diff(1.0), pl);
        // Powers of two are exact shifts, about 2^k hashes per share.
        for k in K_MIN..=K_MAX {
            let t = target_from_diff(diff_of_k(k));
            let w = work_of(&t);
            assert!((w / 2f64.powi(k as i32) - 1.0).abs() < 1e-4, "k {k}: work {w}");
            if k > K_MIN {
                assert!(meets(&t, &target_from_diff(diff_of_k(k - 1))));
            }
        }
    }

    #[test]
    fn hex_fields() {
        assert_eq!(parse_hex32("0000002a"), Some(42));
        assert_eq!(parse_hex32("2a"), None);
        assert_eq!(parse_en2("0a0b0c0d"), Some([10, 11, 12, 13]));
        assert_eq!(swap_words(&swap_words(&[7u8; 32])), [7u8; 32]);
    }
}
