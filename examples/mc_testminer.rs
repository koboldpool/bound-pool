//! Test client for the Miningcore-style ports (3481/3491): BoundCuda 0.2.1's stratum logic (src/boundcuda.cu:
//! connect_, reader, handle_notify, build_header, target_from_diff, submit) ported to Rust, hashing on the CPU.
//! For testing the pool only; real GPU miners use BoundCuda itself.
//!
//!   cargo run --release --example mc_testminer -- -o 127.0.0.1:3481 -u ADDRESS.worker [-t threads] [--seconds N]

use bound_pool::boundhash::{BoundHasher, tagged_hash};
use bound_pool::common::{hex, meets, unhex};
use bound_pool::mcstratum::target_from_diff;
use serde_json::Value;
use std::io::{BufRead, BufReader, Write};
use std::net::TcpStream;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

#[derive(Clone)]
struct Job {
    id: String,
    coinb1: Vec<u8>,
    coinb2: Vec<u8>,
    branches: Vec<Vec<u8>>,
    prev: [u8; 32],
    version: u32,
    bits: u32,
    ntime: u32,
    seq: u64,
}

struct State {
    job: Option<Job>,
    target: [u8; 32],
    diff_seq: u64,
}

fn build_header(j: &Job, en1: &[u8], en2: u32) -> [u8; 80] {
    let mut cb = j.coinb1.clone();
    cb.extend_from_slice(en1);
    cb.extend_from_slice(&en2.to_be_bytes()); // hex order = bytes
    cb.extend_from_slice(&j.coinb2);
    let mut h = tagged_hash("BOUND/wtxid", &cb);
    for br in &j.branches {
        let mut pair = h.to_vec();
        pair.extend_from_slice(br);
        h = tagged_hash("BOUND/merkle", &pair);
    }
    let mut header = [0u8; 80];
    header[0..4].copy_from_slice(&j.version.to_le_bytes());
    header[4..36].copy_from_slice(&j.prev);
    header[36..68].copy_from_slice(&h);
    header[68..72].copy_from_slice(&j.ntime.to_le_bytes());
    header[72..76].copy_from_slice(&j.bits.to_le_bytes());
    header
}

fn parse_notify(p: &Value, seq: u64) -> Option<Job> {
    let it = p.as_array()?;
    let ps = unhex(it[1].as_str()?)?;
    let mut prev = [0u8; 32];
    for i in (0..32).step_by(4) {
        for k in 0..4 {
            prev[i + k] = ps[i + 3 - k];
        }
    }
    let num = |i: usize| it[i].as_str().and_then(|s| u32::from_str_radix(s, 16).ok());
    Some(Job {
        id: it[0].as_str()?.to_string(),
        coinb1: unhex(it[2].as_str()?)?,
        coinb2: unhex(it[3].as_str()?)?,
        branches: it[4].as_array()?.iter().map(|b| unhex(b.as_str().unwrap_or(""))).collect::<Option<Vec<_>>>()?,
        prev,
        version: num(5)?,
        bits: num(6)?,
        ntime: num(7)?,
        seq,
    })
}

fn rand32(seed: &mut u64) -> u32 {
    *seed ^= *seed << 13;
    *seed ^= *seed >> 7;
    *seed ^= *seed << 17;
    (*seed >> 16) as u32
}

fn main() {
    let a: Vec<String> = std::env::args().skip(1).collect();
    let opt = |k: &str, d: &str| a.iter().position(|x| x == k).and_then(|i| a.get(i + 1)).cloned().unwrap_or(d.to_string());
    let (pool, user, pass) = (opt("-o", "127.0.0.1:3481"), opt("-u", ""), opt("-p", "x"));
    let threads: usize = opt("-t", "1").parse().unwrap();
    let seconds: u64 = opt("--seconds", "0").parse().unwrap();
    let s = TcpStream::connect(&pool).expect("connect");
    let mut out = s.try_clone().unwrap();
    let mut rd = BufReader::new(s);
    writeln!(out, "{{\"id\":1,\"method\":\"mining.subscribe\",\"params\":[\"BoundCuda/0.2.1-port\"]}}").unwrap();
    let mut l = String::new();
    let sub: Value = loop {
        l.clear();
        rd.read_line(&mut l).unwrap();
        let v: Value = serde_json::from_str(&l).unwrap();
        if v["id"] == 1 {
            break v;
        }
    };
    let r = sub["result"].as_array().expect("subscribe refused");
    let en1 = unhex(r[1].as_str().unwrap()).unwrap();
    assert_eq!(r[2].as_u64(), Some(4), "extraNonce2 size");
    writeln!(out, "{{\"id\":2,\"method\":\"mining.authorize\",\"params\":[\"{user}\",\"{pass}\"]}}").unwrap();
    println!("subscribed: extraNonce1 {}", hex(&en1));
    let st = Arc::new(Mutex::new(State { job: None, target: target_from_diff(1.0), diff_seq: 0 }));
    let out = Arc::new(Mutex::new(out));
    let (acc, rej, hashes) = (Arc::new(AtomicU64::new(0)), Arc::new(AtomicU64::new(0)), Arc::new(AtomicU64::new(0)));
    {
        let (st, acc, rej) = (st.clone(), acc.clone(), rej.clone());
        std::thread::spawn(move || {
            let mut seq = 0;
            loop {
                let mut l = String::new();
                if rd.read_line(&mut l).unwrap_or(0) == 0 {
                    println!("pool closed the connection");
                    std::process::exit(1);
                }
                let v: Value = serde_json::from_str(&l).unwrap_or(Value::Null);
                match v["method"].as_str() {
                    Some("mining.notify") => {
                        seq += 1;
                        if let Some(j) = parse_notify(&v["params"], seq) {
                            st.lock().unwrap().job = Some(j);
                        }
                    }
                    Some("mining.set_difficulty") => {
                        let d = v["params"][0].as_f64().unwrap();
                        let mut g = st.lock().unwrap();
                        g.target = target_from_diff(d);
                        g.diff_seq += 1;
                        println!("difficulty {d}");
                    }
                    _ => match v["id"].as_u64() {
                        Some(2) => println!("authorize: {}", v["result"]),
                        Some(_) if v["error"].is_null() && v["result"] == true => {
                            acc.fetch_add(1, Ordering::Relaxed);
                        }
                        Some(_) => {
                            rej.fetch_add(1, Ordering::Relaxed);
                            println!("share REJECTED: {}", v["error"]);
                        }
                        None => {}
                    },
                }
            }
        });
    }
    let next_id = Arc::new(AtomicU64::new(3));
    for t in 0..threads {
        let (st, out, en1, hashes, next_id, user) = (st.clone(), out.clone(), en1.clone(), hashes.clone(), next_id.clone(), user.clone());
        std::thread::spawn(move || {
            let mut seed = 0x9e37_79b9_7f4a_7c15u64 ^ (t as u64 + 1) * 0x1234_5678_9abc ^ std::process::id() as u64;
            let mut hasher = BoundHasher::new(4096); // BoundCuda's BOUND_LINES
            let (mut cur, mut dseq) = (0u64, u64::MAX);
            let (mut header, mut target, mut job, mut en2, mut nonce) = ([0u8; 80], [0u8; 32], None::<Job>, 0u32, 0u32);
            loop {
                {
                    let g = st.lock().unwrap();
                    let mut rebuild = false;
                    if let Some(j) = g.job.as_ref().filter(|j| j.seq != cur) {
                        cur = j.seq;
                        job = Some(j.clone());
                        en2 = rand32(&mut seed);
                        rebuild = true;
                    }
                    if g.diff_seq != dseq {
                        dseq = g.diff_seq;
                        target = g.target;
                        rebuild = true;
                    }
                    if rebuild && let Some(j) = &job {
                        header = build_header(j, &en1, en2);
                        nonce = rand32(&mut seed);
                    }
                }
                let Some(j) = &job else {
                    std::thread::sleep(Duration::from_millis(200));
                    continue;
                };
                for _ in 0..32 {
                    header[76..80].copy_from_slice(&nonce.to_le_bytes());
                    if meets(&hasher.hash(&header), &target) {
                        let id = next_id.fetch_add(1, Ordering::Relaxed);
                        let line = format!(
                            "{{\"id\":{id},\"method\":\"mining.submit\",\"params\":[\"{user}\",\"{}\",\"{:08x}\",\"{:08x}\",\"{:08x}\"]}}\n",
                            j.id, en2, j.ntime, nonce
                        );
                        let _ = out.lock().unwrap().write_all(line.as_bytes());
                    }
                    nonce = nonce.wrapping_add(1);
                }
                hashes.fetch_add(32, Ordering::Relaxed);
            }
        });
    }
    let start = Instant::now();
    loop {
        std::thread::sleep(Duration::from_secs(30));
        let el = start.elapsed().as_secs_f64();
        println!(
            "{:.0} H/s, accepted {} rejected {}",
            hashes.load(Ordering::Relaxed) as f64 / el,
            acc.load(Ordering::Relaxed),
            rej.load(Ordering::Relaxed)
        );
        if seconds > 0 && start.elapsed().as_secs() >= seconds {
            std::process::exit(0);
        }
    }
}
