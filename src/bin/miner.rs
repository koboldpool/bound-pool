//! bound-miner: CPU miner for bound-pool/1 pools. `bound-miner -o host:3480 -u <BOUND address>[.worker] [-t threads]`
//! The pool sends a whole header per job; thread i of n rolls its own slice of the 32-bit nonce.

use bound_pool::boundhash::BoundHasher;
use bound_pool::common::*;
use serde_json::{Value, json};
use std::io::{BufRead, BufReader, Write};
use std::net::TcpStream;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex, mpsc};
use std::thread;
use std::time::{Duration, Instant};

struct Args {
    pool: String,
    user: String,
    pass: String,
    threads: usize,
}

fn args() -> Args {
    let mut a = Args {
        pool: "127.0.0.1:3480".into(),
        user: String::new(),
        pass: "x".into(),
        threads: thread::available_parallelism().map(|n| n.get()).unwrap_or(1),
    };
    let v: Vec<String> = std::env::args().skip(1).collect();
    let mut i = 0;
    while i < v.len() {
        let next = v.get(i + 1).cloned().unwrap_or_default();
        match v[i].as_str() {
            "-o" | "--pool" => a.pool = next.trim_start_matches("stratum+tcp://").to_string(),
            "-u" | "--user" => a.user = next,
            "-p" | "--pass" => a.pass = next,
            "-t" | "--threads" => a.threads = next.parse().expect("-t N"),
            "-h" | "--help" => {
                println!("bound-miner -o host:port -u <address>[.worker] [-p password] [-t threads]");
                std::process::exit(0);
            }
            other => panic!("unknown option {other}"),
        }
        i += 2;
    }
    assert!(!a.user.is_empty(), "-u <BOUND address>[.worker] is required");
    a.threads = a.threads.max(1);
    a
}

#[derive(Clone)]
struct Work {
    job_id: String,
    header: [u8; 80],
    target: [u8; 32],
    lines: u32,
    height: u64,
}

struct State {
    work: Mutex<(u64, Option<Work>)>, // (generation, work)
    wake: Condvar,
    hashes: AtomicU64,
    accepted: AtomicU64,
    rejected: AtomicU64,
    connected: AtomicBool,
}

fn worker(st: Arc<State>, index: usize, count: usize, found: mpsc::Sender<(String, u32)>) {
    let mut hasher: Option<BoundHasher> = None;
    let mut generation = 0u64;
    let mut work: Option<Work> = None;
    let slice = (1u64 << 32) / count as u64;
    let mut nonce = 0u64;
    let mut end = 0u64;
    loop {
        {
            let mut w = st.work.lock().unwrap();
            while w.1.is_none() || (work.is_none() && w.0 == generation) {
                w = st.wake.wait(w).unwrap();
            }
            if w.0 != generation {
                generation = w.0;
                work = w.1.clone();
                nonce = index as u64 * slice;
                end = nonce + slice;
            }
        }
        let Some(wk) = work.as_ref() else { continue };
        if hasher.as_ref().is_none_or(|h| h.lines() != wk.lines) {
            hasher = Some(BoundHasher::new(wk.lines));
        }
        let h = hasher.as_mut().unwrap();
        let mut header = wk.header;
        // A slice of work between looks at the job (about 10 ms at mainnet size).
        let stop = (nonce + 64).min(end);
        while nonce < stop {
            header[76..80].copy_from_slice(&(nonce as u32).to_le_bytes());
            if meets(&h.hash(&header), &wk.target) {
                let _ = found.send((wk.job_id.clone(), nonce as u32));
            }
            nonce += 1;
        }
        st.hashes.fetch_add(64, Ordering::Relaxed);
        if nonce >= end {
            // This thread's nonces are used up: wait for the next job (the pool sends one every 30 s).
            work = None;
        }
    }
}

fn session(a: &Args, st: &Arc<State>, found_rx: &mpsc::Receiver<(String, u32)>) -> Result<(), String> {
    let stream = TcpStream::connect(&a.pool).map_err(|e| format!("connect {}: {e}", a.pool))?;
    let _ = stream.set_nodelay(true);
    let mut out = stream.try_clone().map_err(|e| e.to_string())?;
    let send = |out: &mut TcpStream, v: Value| -> Result<(), String> {
        out.write_all(format!("{v}\n").as_bytes()).map_err(|e| e.to_string())
    };
    send(&mut out, json!({"id": 1, "method": "mining.subscribe", "params": [format!("bound-miner/{}", env!("CARGO_PKG_VERSION"))]}))?;
    send(&mut out, json!({"id": 2, "method": "mining.authorize", "params": [a.user, a.pass]}))?;
    st.connected.store(true, Ordering::Relaxed);
    let (line_tx, line_rx) = mpsc::channel::<Option<String>>();
    thread::spawn(move || {
        let mut r = BufReader::new(stream);
        loop {
            let mut l = String::new();
            match r.read_line(&mut l) {
                Ok(0) | Err(_) => {
                    let _ = line_tx.send(None);
                    return;
                }
                Ok(_) => {
                    if line_tx.send(Some(l)).is_err() {
                        return;
                    }
                }
            }
        }
    });
    let mut next_id = 10u64;
    loop {
        while let Ok((job, nonce)) = found_rx.try_recv() {
            next_id += 1;
            send(&mut out, json!({"id": next_id, "method": "mining.submit", "params": [a.user, job, nonce]}))?;
        }
        match line_rx.recv_timeout(Duration::from_millis(50)) {
            Ok(Some(l)) => {
                let Ok(v) = serde_json::from_str::<Value>(&l) else { continue };
                match v.get("method").and_then(|m| m.as_str()) {
                    Some("mining.notify") => {
                        let p = &v["params"][0];
                        let header: Option<[u8; 80]> = p["header"].as_str().and_then(unhex).and_then(|b| b.try_into().ok());
                        let target = p["target"].as_str().and_then(from_display);
                        let (Some(header), Some(target)) = (header, target) else { continue };
                        let w = Work {
                            job_id: p["job_id"].as_str().unwrap_or("").to_string(),
                            header,
                            target,
                            lines: p["lines"].as_u64().unwrap_or(4096) as u32,
                            height: p["height"].as_u64().unwrap_or(0),
                        };
                        if p["clean"].as_bool() == Some(true) {
                            println!("{} new job {} height {} share work {:.0}", now(), w.job_id, w.height, work_of(&w.target));
                        }
                        let mut g = st.work.lock().unwrap();
                        g.0 += 1;
                        g.1 = Some(w);
                        st.wake.notify_all();
                    }
                    _ => {
                        let id = v.get("id").and_then(|x| x.as_u64()).unwrap_or(0);
                        let okv = v.get("result") == Some(&Value::Bool(true));
                        if id == 2 && !okv {
                            return Err(format!("login refused: {}", v["error"]));
                        }
                        if id > 10 {
                            if okv {
                                st.accepted.fetch_add(1, Ordering::Relaxed);
                            } else {
                                st.rejected.fetch_add(1, Ordering::Relaxed);
                                println!("{} share rejected: {}", now(), v["error"]);
                            }
                        }
                    }
                }
            }
            Ok(None) => return Err("pool closed the connection".into()),
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => return Err("reader stopped".into()),
        }
    }
}

fn main() {
    let a = args();
    println!("bound-miner {}: {} threads, pool {}, login {}", env!("CARGO_PKG_VERSION"), a.threads, a.pool, a.user);
    let st = Arc::new(State {
        work: Mutex::new((0, None)),
        wake: Condvar::new(),
        hashes: AtomicU64::new(0),
        accepted: AtomicU64::new(0),
        rejected: AtomicU64::new(0),
        connected: AtomicBool::new(false),
    });
    let (found_tx, found_rx) = mpsc::channel();
    for i in 0..a.threads {
        let (s, f) = (st.clone(), found_tx.clone());
        let n = a.threads;
        thread::spawn(move || worker(s, i, n, f));
    }
    {
        let s = st.clone();
        thread::spawn(move || {
            let mut last = (Instant::now(), 0u64);
            loop {
                thread::sleep(Duration::from_secs(30));
                let h = s.hashes.load(Ordering::Relaxed);
                let rate = (h - last.1) as f64 / last.0.elapsed().as_secs_f64();
                last = (Instant::now(), h);
                println!(
                    "{} {:.0} H/s, shares accepted {} rejected {}",
                    now(),
                    rate,
                    s.accepted.load(Ordering::Relaxed),
                    s.rejected.load(Ordering::Relaxed)
                );
            }
        });
    }
    loop {
        if let Err(e) = session(&a, &st, &found_rx) {
            println!("{} {e}; reconnecting in 5 s", now());
        }
        st.connected.store(false, Ordering::Relaxed);
        {
            let mut g = st.work.lock().unwrap();
            g.0 += 1;
            g.1 = None; // stop hashing stale work while disconnected
        }
        while found_rx.try_recv().is_ok() {}
        thread::sleep(Duration::from_secs(5));
    }
}
