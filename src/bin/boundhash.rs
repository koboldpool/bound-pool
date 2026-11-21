//! boundhash: the Rust BoundHash from the command line.
//!
//!   boundhash --vectors                 the reference vectors, checked (exit 1 on a mismatch)
//!   boundhash <80-byte header hex> [lines]
//!   boundhash --bench [lines] [seconds] [threads]   hashes per second

use bound_pool::boundhash::{BoundHasher, MAINNET_LINES, VECTORS, display, vector_header};
use bound_pool::common::unhex;
use std::time::{Duration, Instant};

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(|s| s.as_str()) {
        Some("--vectors") => {
            let mut bad = 0;
            for (lines, n, want) in VECTORS {
                let got = display(&BoundHasher::new(lines).hash(&vector_header(n)));
                let ok = got == want;
                bad += !ok as i32;
                println!("{lines:>6} {n} {got} {}", if ok { "ok" } else { "MISMATCH" });
            }
            println!("{} of {} vectors match", VECTORS.len() as i32 - bad, VECTORS.len());
            std::process::exit(if bad == 0 { 0 } else { 1 });
        }
        Some("--bench") => {
            let lines = args.get(1).and_then(|s| s.parse().ok()).unwrap_or(MAINNET_LINES);
            let secs = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(10u64);
            let threads = args.get(3).and_then(|s| s.parse().ok()).unwrap_or(1usize);
            let start = Instant::now();
            let handles: Vec<_> = (0..threads)
                .map(|t| {
                    std::thread::spawn(move || {
                        let mut h = BoundHasher::new(lines);
                        let mut header = vector_header(t as u32);
                        let mut n = 0u64;
                        let end = Instant::now() + Duration::from_secs(secs);
                        while Instant::now() < end {
                            for _ in 0..16 {
                                header[76..80].copy_from_slice(&(n as u32).to_le_bytes());
                                std::hint::black_box(h.hash(&header));
                                n += 1;
                            }
                        }
                        n
                    })
                })
                .collect();
            let total: u64 = handles.into_iter().map(|h| h.join().unwrap()).sum();
            let el = start.elapsed().as_secs_f64();
            println!("{lines} lines, {threads} threads: {total} hashes in {el:.1} s = {:.0} H/s", total as f64 / el);
        }
        Some(h) if h.len() == 160 => {
            let lines = args.get(1).and_then(|s| s.parse().ok()).unwrap_or(MAINNET_LINES);
            let header: [u8; 80] = unhex(h).expect("hex").try_into().unwrap();
            println!("{}", display(&BoundHasher::new(lines).hash(&header)));
        }
        _ => {
            eprintln!("boundhash --vectors | --bench [lines] [seconds] [threads] | <header hex> [lines]");
            std::process::exit(2);
        }
    }
}
