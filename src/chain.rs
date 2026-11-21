//! BOUND's block-building pieces a pool needs (BOUND v1.1.0): compact sizes, wtxids, the merkle
//! root, block ids and addresses.

use crate::boundhash::tagged_hash;
use sha2::{Digest, Sha256};

/// Bitcoin's compact size, as BOUND's ByteWriter::compact_size writes it.
pub fn compact_size(n: u64, out: &mut Vec<u8>) {
    if n < 0xfd {
        out.push(n as u8);
    } else if n <= 0xffff {
        out.push(0xfd);
        out.extend_from_slice(&(n as u16).to_le_bytes());
    } else if n <= 0xffff_ffff {
        out.push(0xfe);
        out.extend_from_slice(&(n as u32).to_le_bytes());
    } else {
        out.push(0xff);
        out.extend_from_slice(&n.to_le_bytes());
    }
}

/// The wtxid of a fully serialized transaction: tagged_hash("BOUND/wtxid", serialize()).
pub fn wtxid(tx: &[u8]) -> [u8; 32] {
    tagged_hash("BOUND/wtxid", tx)
}

/// BOUND's merkle tree over wtxids: parent = tagged_hash("BOUND/merkle", left || right); an odd
/// last node is promoted unchanged; one leaf is its own root; no leaves give zero.
pub fn merkle_root(leaves: &[[u8; 32]]) -> [u8; 32] {
    if leaves.is_empty() {
        return [0u8; 32];
    }
    let mut level = leaves.to_vec();
    while level.len() > 1 {
        let mut next = Vec::with_capacity(level.len().div_ceil(2));
        for pair in level.chunks(2) {
            if pair.len() == 2 {
                let mut buf = [0u8; 64];
                buf[..32].copy_from_slice(&pair[0]);
                buf[32..].copy_from_slice(&pair[1]);
                next.push(tagged_hash("BOUND/merkle", &buf));
            } else {
                next.push(pair[0]);
            }
        }
        level = next;
    }
    level[0]
}

pub fn sha256d(data: &[u8]) -> [u8; 32] {
    Sha256::digest(Sha256::digest(data)).into()
}

/// A block's id: SHA-256d of its header (raw byte order; the node shows it reversed).
pub fn block_id(header: &[u8; 80]) -> [u8; 32] {
    sha256d(header)
}

const ALPHABET: &[u8] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

fn base58_decode(s: &str) -> Option<Vec<u8>> {
    let mut num: Vec<u8> = Vec::new(); // big-endian base-256
    for c in s.bytes() {
        let mut carry = ALPHABET.iter().position(|&a| a == c)? as u32;
        for b in num.iter_mut().rev() {
            carry += (*b as u32) * 58;
            *b = carry as u8;
            carry >>= 8;
        }
        while carry > 0 {
            num.insert(0, carry as u8);
            carry >>= 8;
        }
    }
    let zeros = s.bytes().take_while(|&c| c == b'1').count();
    let mut out = vec![0u8; zeros];
    out.extend(num);
    Some(out)
}

/// The address version bytes per network (ConsensusParams::address_version).
pub fn address_version(network: &str) -> Option<&'static [u8]> {
    match network {
        "mainnet" => Some(&[0x46, 0xfb]),
        "testnet" | "regtest" => Some(&[0xf0]),
        _ => None,
    }
}

/// The 32-byte public key an address pays, if `s` is a valid address with this version
/// (base58check of version || key, checksum = first 4 bytes of SHA-256d), as decode_address.
pub fn decode_address(s: &str, version: &[u8]) -> Option<[u8; 32]> {
    if s.len() > 64 {
        return None;
    }
    let raw = base58_decode(s)?;
    if raw.len() != version.len() + 32 + 4 {
        return None;
    }
    let (payload, check) = raw.split_at(raw.len() - 4);
    if sha256d(payload)[..4] != *check || !payload.starts_with(version) {
        return None;
    }
    payload[version.len()..].try_into().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn merkle_shapes() {
        let a = [1u8; 32];
        let b = [2u8; 32];
        let c = [3u8; 32];
        assert_eq!(merkle_root(&[]), [0u8; 32]);
        assert_eq!(merkle_root(&[a]), a);
        let ab = {
            let mut buf = [0u8; 64];
            buf[..32].copy_from_slice(&a);
            buf[32..].copy_from_slice(&b);
            tagged_hash("BOUND/merkle", &buf)
        };
        assert_eq!(merkle_root(&[a, b]), ab);
        // Odd count: c is promoted, not duplicated.
        let abc = {
            let mut buf = [0u8; 64];
            buf[..32].copy_from_slice(&ab);
            buf[32..].copy_from_slice(&c);
            tagged_hash("BOUND/merkle", &buf)
        };
        assert_eq!(merkle_root(&[a, b, c]), abc);
        assert_ne!(merkle_root(&[a, b, c]), merkle_root(&[a, b, c, c]));
    }

    #[test]
    fn compact_sizes() {
        for (n, want) in [(0u64, vec![0u8]), (252, vec![252]), (253, vec![0xfd, 253, 0]), (0x10000, vec![0xfe, 0, 0, 1, 0])] {
            let mut v = Vec::new();
            compact_size(n, &mut v);
            assert_eq!(v, want);
        }
    }

    #[test]
    fn addresses() {
        // The genesis block of mainnet pays the all-zero key; a valid-format check on a made-up key:
        // encode version || key with a correct checksum by hand and decode it back.
        let key = [7u8; 32];
        let mut payload = vec![0x46, 0xfb];
        payload.extend_from_slice(&key);
        let check = sha256d(&payload);
        payload.extend_from_slice(&check[..4]);
        let s = base58_encode(&payload);
        assert!(s.starts_with('B'));
        assert_eq!(s.len(), 52);
        assert_eq!(decode_address(&s, &[0x46, 0xfb]), Some(key));
        assert_eq!(decode_address(&s, &[0xf0]), None);
        let mut bad = s.clone().into_bytes();
        bad[10] = if bad[10] == b'a' { b'b' } else { b'a' };
        assert_eq!(decode_address(std::str::from_utf8(&bad).unwrap(), &[0x46, 0xfb]), None);
    }

    fn base58_encode(data: &[u8]) -> String {
        let mut digits: Vec<u8> = Vec::new();
        for &byte in data {
            let mut carry = byte as u32;
            for d in digits.iter_mut() {
                carry += (*d as u32) << 8;
                *d = (carry % 58) as u8;
                carry /= 58;
            }
            while carry > 0 {
                digits.push((carry % 58) as u8);
                carry /= 58;
            }
        }
        let zeros = data.iter().take_while(|&&b| b == 0).count();
        let mut s = "1".repeat(zeros);
        for d in digits.iter().rev() {
            s.push(ALPHABET[*d as usize] as char);
        }
        s
    }
}
