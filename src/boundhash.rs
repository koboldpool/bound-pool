//! BoundHash, BOUND's proof of work, ported from the node's src/core/boundhash.cpp (v1.1.0, MIT): tagged SHA-256 seed,
//! a scratchpad of `lines` 128-byte lines (4,096 on mainnet) filled with an Argon2-style round, then `lines` mixing steps.
//! Checked against tests/test_boundhash.cpp's vectors (tests at the end of this file).

use sha2::{Digest, Sha256};
use std::sync::LazyLock;

pub const MAINNET_LINES: u32 = 1 << 12;

/// A power of two from 2 to 2^20, as the node requires.
pub fn valid_lines(lines: u32) -> bool {
    (2..=1 << 20).contains(&lines) && lines.is_power_of_two()
}

/// SHA-256 already fed with tag_hash || tag_hash (BIP-340 style tagged hash), cloned per use.
fn tag_state(tag: &str) -> Sha256 {
    let t = Sha256::digest(tag.as_bytes());
    let mut h = Sha256::new();
    h.update(t);
    h.update(t);
    h
}

static SEED_TAG: LazyLock<Sha256> = LazyLock::new(|| tag_state("BOUND/BoundHash"));
static RESULT_TAG: LazyLock<Sha256> = LazyLock::new(|| tag_state("BOUND/BoundHash-result"));

/// tagged_hash(tag, data) = SHA-256(SHA-256(tag) || SHA-256(tag) || data).
pub fn tagged_hash(tag: &str, data: &[u8]) -> [u8; 32] {
    let mut h = tag_state(tag);
    h.update(data);
    h.finalize().into()
}

#[inline(always)]
fn blamka(x: u64, y: u64) -> u64 {
    x.wrapping_add(y).wrapping_add(2u64.wrapping_mul((x as u32 as u64) * (y as u32 as u64)))
}

macro_rules! g {
    ($v:ident, $a:expr, $b:expr, $c:expr, $d:expr) => {
        $v[$a] = blamka($v[$a], $v[$b]);
        $v[$d] = ($v[$d] ^ $v[$a]).rotate_right(32);
        $v[$c] = blamka($v[$c], $v[$d]);
        $v[$b] = ($v[$b] ^ $v[$c]).rotate_right(24);
        $v[$a] = blamka($v[$a], $v[$b]);
        $v[$d] = ($v[$d] ^ $v[$a]).rotate_right(16);
        $v[$c] = blamka($v[$c], $v[$d]);
        $v[$b] = ($v[$b] ^ $v[$c]).rotate_right(63);
    };
}

/// One round on the 16 words: the columns, then the diagonals.
#[inline(always)]
fn round(v: &mut [u64; 16]) {
    g!(v, 0, 4, 8, 12);
    g!(v, 1, 5, 9, 13);
    g!(v, 2, 6, 10, 14);
    g!(v, 3, 7, 11, 15);
    g!(v, 0, 5, 10, 15);
    g!(v, 1, 6, 11, 12);
    g!(v, 2, 7, 8, 13);
    g!(v, 3, 4, 9, 14);
}

/// A scratchpad line from x with its position i as a tweak: one round, then x added back in.
#[inline(always)]
fn fill_line(x: &[u64; 16], i: u64) -> [u64; 16] {
    let mut t = *x;
    t[15] ^= i;
    round(&mut t);
    let mut out = [0u64; 16];
    for k in 0..16 {
        out[k] = t[k] ^ x[k];
    }
    out
}

/// Hashes headers with a scratchpad it allocates once and reuses (one per thread).
pub struct BoundHasher {
    mem: Vec<[u64; 16]>,
    lines: u32,
}

impl BoundHasher {
    /// Panics unless `valid_lines(lines)`.
    pub fn new(lines: u32) -> Self {
        assert!(valid_lines(lines), "BoundHash: lines must be a power of two from 2 to 2^20");
        BoundHasher { mem: vec![[0u64; 16]; lines as usize], lines }
    }

    pub fn lines(&self) -> u32 {
        self.lines
    }

    /// BoundHash of an 80-byte header: 32 bytes, least significant first.
    pub fn hash(&mut self, header: &[u8; 80]) -> [u8; 32] {
        let lines = self.lines as usize;
        let mem = &mut self.mem[..lines];

        // 1. The seed, and the starting state: 16 words from four SHA-256s of it.
        let mut h = SEED_TAG.clone();
        h.update(header);
        let seed: [u8; 32] = h.finalize().into();
        let mut start = [0u64; 16];
        for k in 0..4u8 {
            let mut s = Sha256::new();
            s.update(seed);
            s.update([k]);
            let d: [u8; 32] = s.finalize().into();
            for q in 0..4 {
                start[4 * k as usize + q] = u64::from_le_bytes(d[8 * q..8 * q + 8].try_into().unwrap());
            }
        }

        // 2. Fill: line i from line i - 1 and, from line 2 on, an earlier line in 0 .. i - 2.
        mem[0] = fill_line(&start, 0);
        mem[1] = fill_line(&mem[0], 1);
        for i in 2..lines {
            let prev = mem[i - 1];
            let r = (((prev[0] as u32 as u64) * (i as u64 - 1)) >> 32) as usize;
            let other = &mem[r];
            let mut x = [0u64; 16];
            for k in 0..16 {
                x[k] = prev[k] ^ other[k];
            }
            mem[i] = fill_line(&x, i as u64);
        }

        // 3. Mix: `lines` dependent steps, each reading, multiplying, mixing and writing back.
        let mut v = [0u64; 16];
        for k in 0..16 {
            v[k] = start[k] ^ mem[lines - 1][k];
        }
        let mask = lines - 1;
        for r in 0..lines as u64 {
            let l = &mut mem[(v[0] as usize) & mask];
            for k in 0..16 {
                v[k] ^= l[k];
            }
            let p = (v[0] as u128) * ((v[1] | 1) as u128);
            v[2] = v[2].wrapping_add((p >> 64) as u64);
            v[3] ^= p as u64;
            v[15] ^= r;
            round(&mut v);
            for k in 0..16 {
                l[k] = l[k].wrapping_add(v[k]);
            }
        }

        // 4. The result: tagged SHA-256 of the seed and the final state.
        let mut out = [0u8; 32 + 128];
        out[..32].copy_from_slice(&seed);
        for k in 0..16 {
            out[32 + 8 * k..40 + 8 * k].copy_from_slice(&v[k].to_le_bytes());
        }
        let mut h = RESULT_TAG.clone();
        h.update(out);
        h.finalize().into()
    }
}

/// The hash as block explorers and the node's to_hex() show it: most significant byte first.
pub fn display(hash: &[u8; 32]) -> String {
    let mut r = *hash;
    r.reverse();
    crate::common::hex(&r)
}

/// The headers `tests/test_boundhash.cpp` and `boundhash.py --vectors` hash: version 1,
/// prev = SHA-256("prev n"), merkle = SHA-256("merkle n"), time 1800000000 + n, bits 0x1e03ffff, nonce n.
pub fn vector_header(n: u32) -> [u8; 80] {
    let mut h = [0u8; 80];
    h[0..4].copy_from_slice(&1i32.to_le_bytes());
    h[4..36].copy_from_slice(&Sha256::digest(format!("prev {n}").as_bytes()));
    h[36..68].copy_from_slice(&Sha256::digest(format!("merkle {n}").as_bytes()));
    h[68..72].copy_from_slice(&(1_800_000_000 + n).to_le_bytes());
    h[72..76].copy_from_slice(&0x1e03ffffu32.to_le_bytes());
    h[76..80].copy_from_slice(&n.to_le_bytes());
    h
}

/// The reference vectors, copied from BOUND v1.1.0 `tests/test_boundhash.cpp` (kVectors).
pub const VECTORS: [(u32, u32, &str); 12] = [
    (2, 0, "add6b5b081123141aaf73e33de7c2a232dcb0269966fe043c7c66466e2887ec1"),
    (2, 1, "4daa442458aeb19fc2b101f960c5767d8a6acc61073a46895335b60864a2d9f4"),
    (2, 2, "2b8f5bbbc16f465386a162e4873396f5c04c1ca150a5a8173aefa566919e5d27"),
    (64, 0, "a1da4b56c502232301c7e9b6d05a2a5eb2d14fe2cab122bec8322f662bf05893"),
    (64, 1, "afd16ab5279a240128c41b726f2345e62606855cd39b543ea5328351c3b14eef"),
    (64, 2, "8237b3e10288bb3b85b040ce43360ae68057eb88d1895ed21515cedccd8987ef"),
    (4096, 0, "a1bfe39eba36286133775ee3db0040b7d638827743a25e29a9eb95ab7e42676b"),
    (4096, 1, "b39b4468daa307a37e9758cb2eca618ff93bfde326420c9d4aad728ae8b435de"),
    (4096, 2, "da06793503671e059bf562f81ee8f1e5286bdcf06b0922c8b6365270df29d5df"),
    (16384, 0, "3a78ae5edb5ed9a3d07d2d63460be9a943dbfc287d7a5f1b67d2f5a4592babe2"),
    (16384, 1, "ba513fcd3c8c42024b36ac4282f6a924afde442831d0bf3c70af8d52137e36a6"),
    (16384, 2, "770c5ba0f1af3fdeb5eb0a3f15625a5e1283a9001cc72634712a7b038b4d9d62"),
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_the_reference_vectors() {
        for (lines, n, want) in VECTORS {
            let mut h = BoundHasher::new(lines);
            assert_eq!(display(&h.hash(&vector_header(n))), want, "{lines} lines, header {n}");
        }
    }

    /// One hasher reused across headers gives the same answers as fresh ones (leftovers ignored).
    #[test]
    fn reuse_changes_nothing() {
        let mut h = BoundHasher::new(64);
        for _ in 0..3 {
            for n in 0..3 {
                assert_eq!(display(&h.hash(&vector_header(n))), VECTORS[3 + n as usize].2);
            }
        }
    }

    #[test]
    fn every_header_bit_matters() {
        let mut h = BoundHasher::new(64);
        let base = vector_header(7);
        let mut seen = std::collections::HashSet::new();
        seen.insert(h.hash(&base));
        for bit in 0..640 {
            let mut f = base;
            f[bit / 8] ^= 1 << (bit % 8);
            assert!(seen.insert(h.hash(&f)), "bit {bit}");
        }
    }

    #[test]
    fn line_counts() {
        for ok in [2, 64, 4096, 1 << 20] {
            assert!(valid_lines(ok));
        }
        for bad in [0, 1, 3, 96, (1 << 20) + 1, 1 << 21] {
            assert!(!valid_lines(bad));
        }
    }
}
