//! The Miningcore-style dialect against real BOUND data (BOUND testnet rules, Kobold Pool's private test chain):
//! a block with five transactions mined through the pool, and a node template. The miner side is BoundCuda
//! 0.2.1's logic (handle_notify + build_header, src/boundcuda.cu), ported: it reads only the notify's JSON.

use bound_pool::boundhash::{BoundHasher, tagged_hash};
use bound_pool::chain::{merkle_root, wtxid};
use bound_pool::common::{from_display, meets, unhex};
use bound_pool::mcstratum as mc;
use serde_json::Value;

const TAG: &[u8] = b"KoboldPool";

/// BoundCuda's build_header from a notify, extraNonce1 (hex), extraNonce2 (u32) and nonce.
fn boundcuda_header(notify: &Value, en1_hex: &str, en2: u32, nonce: u32) -> [u8; 80] {
    let it = notify.as_array().unwrap();
    let ps = unhex(it[1].as_str().unwrap()).unwrap();
    let mut prev = [0u8; 32];
    for i in (0..32).step_by(4) {
        prev[i] = ps[i + 3];
        prev[i + 1] = ps[i + 2];
        prev[i + 2] = ps[i + 1];
        prev[i + 3] = ps[i];
    }
    let mut cb = unhex(it[2].as_str().unwrap()).unwrap();
    cb.extend(unhex(en1_hex).unwrap());
    cb.extend(en2.to_be_bytes()); // hex order = bytes
    cb.extend(unhex(it[3].as_str().unwrap()).unwrap());
    let mut h = tagged_hash("BOUND/wtxid", &cb);
    for b in it[4].as_array().unwrap() {
        let mut pair = h.to_vec();
        pair.extend(unhex(b.as_str().unwrap()).unwrap());
        h = tagged_hash("BOUND/merkle", &pair);
    }
    let num = |i: usize| u32::from_str_radix(it[i].as_str().unwrap(), 16).unwrap();
    let mut header = [0u8; 80];
    header[0..4].copy_from_slice(&num(5).to_le_bytes());
    header[4..36].copy_from_slice(&prev);
    header[36..68].copy_from_slice(&h);
    header[68..72].copy_from_slice(&num(7).to_le_bytes());
    header[72..76].copy_from_slice(&num(6).to_le_bytes());
    header[76..80].copy_from_slice(&nonce.to_le_bytes());
    header
}

fn compact_size(b: &[u8], pos: &mut usize) -> usize {
    let t = b[*pos];
    *pos += 1;
    let n = match t {
        0xfd => 2,
        0xfe => 4,
        0xff => 8,
        _ => return t as usize,
    };
    let mut v = 0usize;
    for i in 0..n {
        v |= (b[*pos + i] as usize) << (8 * i);
    }
    *pos += n;
    v
}

/// Splits a serialized block into header and transactions (BOUND's format: version, inputs (txid, index),
/// outputs (amount, key), lock_time, memo, then one 64-byte signature per input).
fn split_block(b: &[u8]) -> ([u8; 80], Vec<Vec<u8>>) {
    let header: [u8; 80] = b[..80].try_into().unwrap();
    let mut pos = 80;
    let n = compact_size(b, &mut pos);
    let mut txs = Vec::new();
    for _ in 0..n {
        let start = pos;
        pos += 4;
        let ins = compact_size(b, &mut pos);
        pos += ins * 36;
        let outs = compact_size(b, &mut pos);
        pos += outs * 40 + 4;
        let memo = compact_size(b, &mut pos);
        pos += memo + ins * 64;
        txs.push(b[start..pos].to_vec());
    }
    assert_eq!(pos, b.len());
    (header, txs)
}

fn compact_target(bits: u32) -> [u8; 32] {
    let mut t = [0u8; 32];
    let exp = (bits >> 24) as usize;
    let mant = bits & 0x007f_ffff;
    for i in 0..3 {
        t[exp - 3 + i] = (mant >> (8 * i)) as u8;
    }
    t
}

#[test]
fn a_real_block_rebuilds_from_the_notify() {
    let raw = unhex(include_str!("data/testnet-block-181.hex").trim()).unwrap();
    let (real, txs) = split_block(&raw);
    assert_eq!(txs.len(), 5, "coinbase + 4 payouts");
    // Its coinbase memo is KoboldPool || 4-byte extranonce1 || 4 more bytes: the dialect's tag || en1 || en2.
    let cb = &txs[0];
    let memo_at = cb.len() - (TAG.len() + 8);
    assert_eq!(cb[memo_at - 1] as usize, TAG.len() + 8);
    assert_eq!(&cb[memo_at..memo_at + TAG.len()], TAG);
    let en1 = &cb[memo_at + TAG.len()..memo_at + TAG.len() + 4];
    let en2 = u32::from_be_bytes(cb[cb.len() - 4..].try_into().unwrap());
    let others: Vec<[u8; 32]> = txs[1..].iter().map(|t| wtxid(t)).collect();

    let work = mc::build_work(&cb[..memo_at - 1], TAG, &real, &others);
    assert_eq!(work.coinb1, cb[..memo_at + TAG.len()].to_vec());
    assert_eq!(work.branches.len(), 3); // 5 leaves: 3 levels below the root
    let notify = mc::notify_params("1", &work, true);
    let ntime = u32::from_le_bytes(real[68..72].try_into().unwrap());
    let nonce = u32::from_le_bytes(real[76..80].try_into().unwrap());

    // The miner's header, the pool's header and the real header are the same 80 bytes.
    let miner = boundcuda_header(&notify, &bound_pool::common::hex(en1), en2, nonce);
    assert_eq!(miner, real);
    assert_eq!(mc::header(&work, en1, &en2.to_be_bytes(), ntime, nonce), real);
    // Their merkle root is the full tree's, and the header's BoundHash meets the block's target.
    let mut leaves = vec![wtxid(cb)];
    leaves.extend_from_slice(&others);
    assert_eq!(real[36..68], merkle_root(&leaves));
    let bits = u32::from_le_bytes(real[72..76].try_into().unwrap());
    assert!(meets(&BoundHasher::new(4096).hash(&real), &compact_target(bits)));
    // And the submit's fields round-trip as BoundCuda prints them ("%08x").
    assert_eq!(mc::parse_hex32(&format!("{nonce:08x}")), Some(nonce));
    assert_eq!(mc::parse_en2(&format!("{en2:08x}")), Some(en2.to_be_bytes()));
}

#[test]
fn a_real_template_gives_the_pool_header() {
    let t: Value = serde_json::from_str(include_str!("data/testnet-template.json")).unwrap();
    let header: [u8; 80] = unhex(t["header"].as_str().unwrap()).unwrap().try_into().unwrap();
    let coinbase = unhex(t["coinbase"].as_str().unwrap()).unwrap();
    let prefix = &coinbase[..coinbase.len() - 9]; // the node's 8-byte zero memo, last
    let others: Vec<[u8; 32]> =
        t["transactions"].as_array().unwrap().iter().map(|x| from_display(x["wtxid"].as_str().unwrap()).unwrap()).collect();
    let work = mc::build_work(prefix, TAG, &header, &others);
    let notify = mc::notify_params("2a", &work, false);
    assert_eq!(notify[8], Value::Bool(false));
    assert_eq!(notify[6].as_str().unwrap(), t["bits"].as_str().unwrap());
    let (en1, en2, nonce) = ([0x11, 0x22, 0x33, 0x44], 0xdeadbeefu32, 12345u32);
    let miner = boundcuda_header(&notify, "11223344", en2, nonce);
    let ntime = u32::from_le_bytes(header[68..72].try_into().unwrap());
    assert_eq!(miner, mc::header(&work, &en1, &en2.to_be_bytes(), ntime, nonce));
    // Same as building the block the bound-pool/1 way: memo = tag || en1 || en2, root over all leaves.
    let mut cb = prefix.to_vec();
    cb.push((TAG.len() + 8) as u8);
    cb.extend_from_slice(TAG);
    cb.extend_from_slice(&en1);
    cb.extend_from_slice(&en2.to_be_bytes());
    let mut leaves = vec![wtxid(&cb)];
    leaves.extend_from_slice(&others);
    let mut want = header;
    want[36..68].copy_from_slice(&merkle_root(&leaves));
    want[76..80].copy_from_slice(&nonce.to_le_bytes());
    assert_eq!(miner, want);
    assert_eq!(miner[4..36], header[4..36]); // parent survives the word swap both ways
}
