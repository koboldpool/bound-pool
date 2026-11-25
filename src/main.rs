//! bound-pool: Kobold Pool's BOUND pool (stratum bound-pool/1, JSON lines). Polls a boundd patched with
//! getblocktemplate/submitblock, gives each session its own header (pool tag + extranonce1 + job counter in the coinbase),
//! re-hashes every submit with the Rust BoundHash. Same data files as neb-pool, so the site and payout.py read them.

use bound_pool::boundhash::{BoundHasher, valid_lines};
use bound_pool::chain::{address_version, block_id, compact_size, decode_address, merkle_root, wtxid};
use bound_pool::common::*;
use bound_pool::mcstratum as mc;
use bound_pool::rpc::Rpc;
use ed25519_dalek::{Signer, SigningKey};
use serde_json::{Value, json};
use std::collections::{HashMap, HashSet, VecDeque};
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

const MAX_LINE: usize = 16_384;
/// Jobs a session keeps for late submits.
const KEEP_JOBS: usize = 16;

/// What the pool signs for a locked miner: the domain, the miner's challenge, then the job as sent.
fn lock_message(challenge: &[u8; 32], job_id: &str, header: &[u8; 80], target: &[u8; 32]) -> Vec<u8> {
    let mut m = b"kobold-pool-lock/1".to_vec();
    m.extend_from_slice(challenge);
    m.extend_from_slice(header);
    m.extend_from_slice(target);
    m.extend_from_slice(job_id.as_bytes());
    m
}

fn lock_key(path: &std::path::Path) -> Result<SigningKey, String> {
    let b = std::fs::read(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let seed: [u8; 32] = b.as_slice().try_into().map_err(|_| format!("{}: not 32 bytes", path.display()))?;
    Ok(SigningKey::from_bytes(&seed))
}
/// Pool share target = 2^(256-k) - 1 (about 2^k hashes per share), never harder than the block's.
const K_MIN: u32 = 4;
const K_MAX: u32 = 60;
/// Vardiff aims at about one share every 10 s: it retunes after VARDIFF_WINDOW.
const VARDIFF_WINDOW: Duration = Duration::from_secs(60);
const RATE_LOW: usize = 3; // fewer per window: easier
const RATE_HIGH: usize = 12; // more per window: harder
const MAX_SUBMITS_PER_SEC: usize = 25;
const MAX_BAD_IN_A_ROW: u32 = 30;
const HASHRATE_WINDOW: Duration = Duration::from_secs(600);
/// A fresh template this often even without a new block (new transactions, a newer time).
const REFRESH: Duration = Duration::from_secs(30);

struct Config {
    network: String,
    listen: String,
    /// Every login on this port mines solo.
    listen_solo: String,
    /// The Miningcore-style dialect (BoundCuda and similar GPU miners): PPLNS and solo ports ("off": none).
    listen_mc: String,
    listen_mc_solo: String,
    rpc: String,
    cookie: PathBuf,
    /// The pool wallet's address: every block's coinbase pays it.
    address: String,
    data: PathBuf,
    start_k: u32,
    name: String,
    tag: String,
    /// No work while the node's tip is older than this (seconds; 0 = no limit): still syncing.
    max_tip_age: u64,
    /// No work with fewer peers than this (default 1 on mainnet, 0 elsewhere): never mine a private fork.
    min_peers: usize,
    /// 32-byte Ed25519 seed: with it, every job to a miner that sent a lock challenge is signed (pool lock).
    lock_key: PathBuf,
}

fn config() -> Config {
    let mut c = Config {
        network: "mainnet".into(),
        listen: "0.0.0.0:3480".into(),
        listen_solo: "0.0.0.0:3490".into(),
        listen_mc: "0.0.0.0:3481".into(),
        listen_mc_solo: "0.0.0.0:3491".into(),
        rpc: String::new(),
        cookie: PathBuf::new(),
        address: String::new(),
        data: "pool-data".into(),
        start_k: 16,
        name: "bound-pool".into(),
        tag: "KoboldPool".into(),
        max_tip_age: 86_400,
        min_peers: usize::MAX, // set below from the network
        lock_key: PathBuf::new(),
    };
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut i = 0;
    while i < args.len() {
        let v = args.get(i + 1).cloned().unwrap_or_default();
        match args[i].as_str() {
            "--network" => c.network = v,
            "--listen" => c.listen = v,
            "--listen-solo" => c.listen_solo = v,
            "--listen-mc" => c.listen_mc = v,
            "--listen-mc-solo" => c.listen_mc_solo = v,
            "--rpc" => c.rpc = v,
            "--cookie" => c.cookie = v.into(),
            "--address" => c.address = v,
            "--data" => c.data = v.into(),
            "--start-k" => c.start_k = v.parse().expect("--start-k N"),
            "--name" => c.name = v,
            "--tag" => c.tag = v,
            "--max-tip-age" => c.max_tip_age = v.parse().expect("--max-tip-age seconds"),
            "--min-peers" => c.min_peers = v.parse().expect("--min-peers N"),
            "--lock-key" => c.lock_key = v.into(),
            "--lock-pubkey" => {
                let key = lock_key(std::path::Path::new(&v)).expect("--lock-pubkey <key file>");
                println!("{}", hex(key.verifying_key().as_bytes()));
                std::process::exit(0);
            }
            "--help" | "-h" => {
                println!(
                    "bound-pool --address <pool wallet address> --cookie <boundd datadir>/.cookie [--network mainnet|testnet|regtest] \
                     [--rpc 127.0.0.1:7332] [--listen 0.0.0.0:3480] [--listen-solo 0.0.0.0:3490]                      [--listen-mc 0.0.0.0:3481|off] [--listen-mc-solo 0.0.0.0:3491|off] [--data pool-data] [--start-k 16] \
                     [--name bound-pool] [--tag KoboldPool] [--max-tip-age 86400] [--min-peers 1 on mainnet, else 0] [--lock-key <file>]
                     bound-pool --lock-pubkey <file>   prints the public key of a lock key"
                );
                std::process::exit(0);
            }
            other => panic!("unknown option {other}"),
        }
        i += 2;
    }
    if c.rpc.is_empty() {
        c.rpc = match c.network.as_str() {
            "mainnet" => "127.0.0.1:7332",
            "testnet" => "127.0.0.1:18332",
            "regtest" => "127.0.0.1:18543",
            other => panic!("--network mainnet|testnet|regtest, not {other}"),
        }
        .into();
    }
    if c.min_peers == usize::MAX {
        c.min_peers = if c.network == "mainnet" { 1 } else { 0 };
    }
    assert!(c.tag.len() <= 80, "--tag at most 80 bytes (the memo holds 100)");
    c
}

/// A block template from the node.
struct Template {
    height: u32,
    /// The parent, raw byte order (as in the header).
    prev: [u8; 32],
    bits: u32,
    /// The block target, little-endian.
    target: [u8; 32],
    lines: u32,
    /// The node's header (nonce 0); the merkle root is replaced per job.
    header: [u8; 80],
    /// The coinbase without its memo (var_bytes, last): a job appends its own.
    coinbase_prefix: Vec<u8>,
    txs: Vec<Vec<u8>>,
    wtxids: Vec<[u8; 32]>,
    created: Instant,
    /// The node is still catching up (its initial_sync flag).
    initial_sync: bool,
    /// The median time past of the tip, + 1 (Unix seconds).
    mintime: u64,
}

fn parse_template(v: &Value) -> Result<Template, String> {
    let s = |k: &str| v.get(k).and_then(|x| x.as_str()).ok_or(format!("template without {k}"));
    let header: [u8; 80] = unhex(s("header")?).and_then(|b| b.try_into().ok()).ok_or("bad header")?;
    let coinbase = unhex(s("coinbase")?).ok_or("bad coinbase")?;
    // The node's memo is an 8-byte extra nonce of zeros, last: var_bytes = 0x08 + 8 bytes.
    if coinbase.len() < 9 || coinbase[coinbase.len() - 9] != 8 {
        return Err("coinbase does not end with an 8-byte memo".into());
    }
    let mut txs = Vec::new();
    let mut wtxids = Vec::new();
    for t in v.get("transactions").and_then(|x| x.as_array()).ok_or("no transactions")? {
        let data = unhex(t.get("data").and_then(|x| x.as_str()).ok_or("tx without data")?).ok_or("bad tx hex")?;
        let w = wtxid(&data);
        // Cross-check with the node's own wtxid.
        if t.get("wtxid").and_then(|x| x.as_str()).and_then(from_display) != Some(w) {
            return Err("transaction wtxid does not match".into());
        }
        txs.push(data);
        wtxids.push(w);
    }
    let lines = v.get("pow_lines").and_then(|x| x.as_u64()).ok_or("no pow_lines")? as u32;
    if !valid_lines(lines) {
        return Err(format!("pow_lines {lines} not valid"));
    }
    Ok(Template {
        height: v.get("height").and_then(|x| x.as_u64()).ok_or("no height")? as u32,
        prev: header[4..36].try_into().unwrap(),
        bits: u32::from_str_radix(s("bits")?, 16).map_err(|_| "bad bits")?,
        target: from_display(s("target")?).ok_or("bad target")?,
        lines,
        header,
        coinbase_prefix: coinbase[..coinbase.len() - 9].to_vec(),
        txs,
        wtxids,
        created: Instant::now(),
        initial_sync: v.get("initial_sync").and_then(|x| x.as_bool()).unwrap_or(false),
        mintime: v.get("mintime").and_then(|x| x.as_u64()).unwrap_or(0),
    })
}

/// One job of one session: its own header, from its own coinbase memo.
struct Job {
    id: String,
    tmpl: Arc<Template>,
    memo: Vec<u8>,
    header: [u8; 80],
    /// The share target this job was given with: submits on it are judged by it.
    target: [u8; 32],
    nonces: HashSet<u32>,
}

impl Job {
    fn coinbase(&self) -> Vec<u8> {
        let mut cb = self.tmpl.coinbase_prefix.clone();
        compact_size(self.memo.len() as u64, &mut cb);
        cb.extend_from_slice(&self.memo);
        cb
    }

    fn block(&self, header: &[u8; 80]) -> Vec<u8> {
        let mut b = header.to_vec();
        compact_size(1 + self.tmpl.txs.len() as u64, &mut b);
        b.extend_from_slice(&self.coinbase());
        for t in &self.tmpl.txs {
            b.extend_from_slice(t);
        }
        b
    }
}

/// A job of the Miningcore-style dialect: one per template, shared by its sessions (each adds its own
/// extraNonce1, and the miner its extraNonce2).
struct McJob {
    id: String,
    tmpl: Arc<Template>,
    work: mc::McWork,
}

impl McJob {
    fn block(&self, header: &[u8; 80], coinbase: &[u8]) -> Vec<u8> {
        let mut b = header.to_vec();
        compact_size(1 + self.tmpl.txs.len() as u64, &mut b);
        b.extend_from_slice(coinbase);
        for t in &self.tmpl.txs {
            b.extend_from_slice(t);
        }
        b
    }
}

#[derive(Default)]
struct Counters {
    accepted: AtomicU64,
    rejected: AtomicU64,
    stale: AtomicU64,
    blocks_submitted: AtomicU64,
    blocks_accepted: AtomicU64,
}

struct Shared {
    cfg: Config,
    version: &'static [u8],
    rpc: Rpc,
    tmpl: Mutex<Option<Arc<Template>>>,
    mc_jobs: Mutex<VecDeque<Arc<McJob>>>,
    sessions: Mutex<Vec<Arc<Session>>>,
    /// Recent accepted shares for the hash rate: (time, address, worker, work, solo).
    recent: Mutex<VecDeque<(Instant, String, String, f64, bool)>>,
    next_session: AtomicU64,
    next_job: AtomicU64,
    next_en1: AtomicU32,
    node_up: AtomicBool,
    peers: AtomicUsize,
    refresh_now: AtomicBool,
    /// The parent of the pool's last block that became the tip: jobs on it are stale at once, before
    /// the node loop has fetched the next template (else shares in that gap became orphan blocks).
    solved_parent: Mutex<Option<[u8; 32]>>,
    lock_key: Option<SigningKey>,
    /// Fees in basis points (100 = 1 %), from <data>/pool-config.json, re-read every 10 s.
    fee_bp: AtomicU32,
    solo_fee_bp: AtomicU32,
    /// Share work since the pool's last block: effort = round work / block work.
    round_work: Mutex<f64>,
    counters: Counters,
    files: Mutex<(File, File, File, File)>, // shares.jsonl, blocks.jsonl, pool.log, rejects.jsonl
    started: u64,
}

impl Shared {
    fn log(&self, msg: &str) {
        let line = format!("{} {msg}\n", now());
        print!("{line}");
        if let Ok(mut f) = self.files.lock() {
            let _ = f.2.write_all(line.as_bytes());
        }
    }

    fn record(&self, which: usize, v: Value) {
        if let Ok(mut f) = self.files.lock() {
            let file = match which {
                0 => &mut f.0,
                1 => &mut f.1,
                _ => &mut f.3, // REJECTS
            };
            let _ = writeln!(file, "{v}");
        }
    }

    fn current(&self) -> Option<Arc<Template>> {
        self.tmpl.lock().unwrap().clone()
    }
}

struct SessState {
    subscribed: bool,
    en1: [u8; 4],
    logins: HashSet<String>,
    /// Logins that mine in solo mode (authorized with a password containing "solo").
    solo: HashSet<String>,
    k: u32,
    jobs: VecDeque<Job>,
    window_start: Instant,
    window_count: usize,
    second: (Instant, usize),
    bad_in_a_row: u32,
    /// The miner's lock challenge from mining.subscribe: its jobs carry the pool's signature over it.
    lock: Option<[u8; 32]>,
    /// Miningcore-style dialect: the k of the last set_difficulty, the one before it (accepted for 30 s
    /// after a change) and the shares seen (job, extraNonce2, ntime, nonce).
    mc_k: Option<u32>,
    mc_prev: Option<(u32, Instant)>,
    mc_seen: HashSet<(String, [u8; 4], u32, u32)>,
}

struct Session {
    id: u64,
    peer: String,
    solo_port: bool,
    /// Speaks the Miningcore-style dialect (ports 3481/3491), not bound-pool/1.
    mc: bool,
    out: Mutex<TcpStream>,
    st: Mutex<SessState>,
    alive: AtomicBool,
}

impl Session {
    fn send(&self, v: &Value) {
        let mut line = v.to_string();
        line.push('\n');
        let ok = self.out.lock().map(|mut s| s.write_all(line.as_bytes()).is_ok()).unwrap_or(false);
        if !ok {
            self.alive.store(false, Ordering::Relaxed);
        }
    }

    fn notify(&self, method: &str, params: Value) {
        self.send(&json!({"id": null, "method": method, "params": params}));
    }
}

/// Makes the session a new job on `tmpl` (its own memo, merkle root and header) and sends it.
fn push_job(sh: &Shared, sess: &Session, tmpl: &Arc<Template>, clean: bool) {
    if sess.mc {
        push_job_mc(sh, sess, tmpl, clean);
        return;
    }
    let counter = sh.next_job.fetch_add(1, Ordering::Relaxed);
    let msg = {
        let mut st = sess.st.lock().unwrap();
        if st.logins.is_empty() {
            return;
        }
        let mut memo = sh.cfg.tag.as_bytes().to_vec();
        memo.extend_from_slice(&st.en1);
        memo.extend_from_slice(&(counter as u32).to_le_bytes());
        let mut job = Job {
            id: format!("{counter:x}"),
            tmpl: tmpl.clone(),
            memo,
            header: tmpl.header,
            target: easier(target_of_k(st.k), tmpl.target),
            nonces: HashSet::new(),
        };
        let mut leaves = vec![wtxid(&job.coinbase())];
        leaves.extend_from_slice(&tmpl.wtxids);
        job.header[36..68].copy_from_slice(&merkle_root(&leaves));
        let mut msg = json!([{
            "job_id": job.id, "clean": clean, "header": hex(&job.header), "target": to_display(&job.target),
            "height": tmpl.height, "lines": tmpl.lines, "bits": format!("{:08x}", tmpl.bits)
        }]);
        if let (Some(key), Some(ch)) = (&sh.lock_key, &st.lock) {
            msg[0]["sig"] = json!(hex(&key.sign(&lock_message(ch, &job.id, &job.header, &job.target)).to_bytes()));
        }
        st.jobs.push_back(job);
        while st.jobs.len() > KEEP_JOBS {
            st.jobs.pop_front();
        }
        msg
    };
    sess.notify("mining.notify", msg);
}

// ------------------------------------------------------------------------------------- node link

/// Polls the node: a new template when the tip changes, after a found block, or every REFRESH.
fn node_loop(sh: Arc<Shared>) {
    let mut last_tip = String::new();
    let mut waiting = false;
    let mut last_peers = Instant::now() - Duration::from_secs(60);
    loop {
        let tip = sh.rpc.call("getbestblockhash", json!([]));
        match tip {
            Ok(Value::String(tip)) => {
                if !sh.node_up.swap(true, Ordering::Relaxed) {
                    sh.log(&format!("node RPC {} up", sh.cfg.rpc));
                }
                let stale = sh.current().is_none_or(|t| t.created.elapsed() >= REFRESH);
                let clean = tip != last_tip;
                if clean || stale || sh.refresh_now.swap(false, Ordering::Relaxed) {
                    match sh.rpc.call("getblocktemplate", json!([sh.cfg.address])).and_then(|v| parse_template(&v)) {
                        Ok(t) => {
                            let age = now().saturating_sub(t.mintime);
                            let peers = sh.peers.load(Ordering::Relaxed);
                            let why = if t.initial_sync {
                                Some("the node is still syncing".to_string())
                            } else if sh.cfg.max_tip_age > 0 && age > sh.cfg.max_tip_age {
                                Some(format!("the tip is {} h old (still syncing?)", age / 3600))
                            } else if peers < sh.cfg.min_peers {
                                Some(format!("the node has {peers} peers"))
                            } else {
                                None
                            };
                            if let Some(why) = why {
                                if sh.tmpl.lock().unwrap().take().is_some() || !waiting {
                                    sh.log(&format!("no work for miners: {why}; waiting"));
                                }
                                waiting = true;
                                last_tip.clear();
                            } else {
                                if waiting {
                                    sh.log("node ready: handing out work");
                                }
                                waiting = false;
                                last_tip = tip;
                                install(&sh, t, clean);
                            }
                        }
                        Err(e) => sh.log(&format!("getblocktemplate failed: {e}")),
                    }
                }
                if last_peers.elapsed() >= Duration::from_secs(10) {
                    last_peers = Instant::now();
                    if let Ok(n) = sh.rpc.call("getconnectioncount", json!([])) {
                        sh.peers.store(n.as_u64().unwrap_or(0) as usize, Ordering::Relaxed);
                    }
                }
            }
            Ok(other) => sh.log(&format!("getbestblockhash: unexpected {other}")),
            Err(e) => {
                if sh.node_up.swap(false, Ordering::Relaxed) {
                    sh.log(&format!("node RPC down: {e}"));
                }
                thread::sleep(Duration::from_secs(2));
            }
        }
        thread::sleep(Duration::from_millis(if waiting { 5000 } else { 500 }));
    }
}

fn install(sh: &Arc<Shared>, t: Template, clean: bool) {
    let t = Arc::new(t);
    *sh.tmpl.lock().unwrap() = Some(t.clone());
    if clean {
        sh.log(&format!(
            "new block template: height {} bits {:08x} txs {} lines {}",
            t.height,
            t.bits,
            t.txs.len(),
            t.lines
        ));
    }
    let sessions: Vec<Arc<Session>> = sh.sessions.lock().unwrap().clone();
    for s in sessions {
        if s.alive.load(Ordering::Relaxed) {
            push_job(sh, &s, &t, clean);
        }
    }
}

// ------------------------------------------------------------------------------------- miners

/// Which file `Shared::record` writes to: one line per refused share, for our monitoring only (the site never reads it).
const REJECTS: usize = 2;

/// A refused submit (any error answer) as one line in rejects.jsonl.
fn log_reject(sh: &Shared, sess: &Session, p: &[Value], reply: &Value) {
    let Some(e) = reply.get("error").filter(|e| !e.is_null()) else { return };
    let who = p.first().and_then(|v| v.as_str()).unwrap_or("");
    let (addr, worker) = who.split_once('.').unwrap_or((who, ""));
    let reason = e.get(1).and_then(|v| v.as_str()).unwrap_or("");
    sh.record(REJECTS, json!({"ts": now(), "addr": addr, "worker": worker, "ip": sess.peer,
        "reason": reason, "stale": reason.contains("stale")}));
}

fn err(id: &Value, code: u32, msg: &str) -> Value {
    json!({"id": id, "result": null, "error": [code, msg]})
}

fn ok(id: &Value, result: Value) -> Value {
    json!({"id": id, "result": result, "error": null})
}

/// "<address>[.worker]" with a valid address of the pool's network: (address, worker).
fn valid_login(version: &[u8], login: &str) -> Option<(String, String)> {
    let (addr, worker) = match login.split_once('.') {
        Some((a, w)) => (a, w),
        None => (login, ""),
    };
    if worker.len() > 32 || !worker.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-') {
        return None;
    }
    decode_address(addr, version)?;
    Some((addr.to_string(), if worker.is_empty() { "default".into() } else { worker.to_string() }))
}

fn serve_miner(sh: Arc<Shared>, stream: TcpStream, solo_port: bool, mc_dialect: bool) {
    let peer = stream.peer_addr().map(|a| a.to_string()).unwrap_or_default();
    let _ = stream.set_nodelay(true);
    let _ = stream.set_read_timeout(Some(Duration::from_secs(600)));
    let Ok(out) = stream.try_clone() else { return };
    let id = sh.next_session.fetch_add(1, Ordering::Relaxed);
    let en1 = sh.next_en1.fetch_add(1, Ordering::Relaxed).to_le_bytes();
    let sess = Arc::new(Session {
        id,
        peer: peer.clone(),
        solo_port,
        mc: mc_dialect,
        out: Mutex::new(out),
        alive: AtomicBool::new(true),
        st: Mutex::new(SessState {
            subscribed: false,
            en1,
            logins: HashSet::new(),
            solo: HashSet::new(),
            k: sh.cfg.start_k,
            jobs: VecDeque::new(),
            window_start: Instant::now(),
            window_count: 0,
            second: (Instant::now(), 0),
            bad_in_a_row: 0,
            lock: None,
            mc_k: None,
            mc_prev: None,
            mc_seen: HashSet::new(),
        }),
    });
    sh.sessions.lock().unwrap().push(sess.clone());
    let mut reader = BufReader::new(stream);
    let mut hasher: Option<BoundHasher> = None;
    let mut line = String::new();
    loop {
        line.clear();
        match (&mut reader).take(MAX_LINE as u64 + 1).read_line(&mut line) {
            Ok(0) | Err(_) => break,
            Ok(n) if n > MAX_LINE => break,
            Ok(_) => {}
        }
        if line.trim().is_empty() {
            continue;
        }
        let Ok(req) = serde_json::from_str::<Value>(&line) else { break };
        let rid = req.get("id").cloned().unwrap_or(Value::Null);
        let p = req.get("params").and_then(|v| v.as_array()).cloned().unwrap_or_default();
        let method = req.get("method").and_then(|m| m.as_str()).unwrap_or("");
        let reply = match method {
            "mining.subscribe" if sess.mc => subscribe_mc(&sh, &sess, &rid),
            "mining.subscribe" => subscribe(&sh, &sess, &rid, &p),
            "mining.authorize" => authorize(&sh, &sess, &rid, &p),
            "mining.submit" if sess.mc => {
                let r = submit_mc(&sh, &sess, &rid, &p, &mut hasher);
                log_reject(&sh, &sess, &p, &r);
                r
            }
            "mining.submit" => {
                let r = submit(&sh, &sess, &rid, &p, &mut hasher);
                log_reject(&sh, &sess, &p, &r);
                r
            }
            "mining.suggest_difficulty" | "mining.suggest_target" | "mining.extranonce.subscribe" => ok(&rid, json!(true)),
            _ => err(&rid, 20, "unknown method"),
        };
        sess.send(&reply);
        if !sess.alive.load(Ordering::Relaxed) {
            break;
        }
        if method == "mining.authorize" && reply.get("result") == Some(&Value::Bool(true)) {
            let first = sess.st.lock().unwrap().logins.len() == 1;
            if first {
                if let Some(t) = sh.current() {
                    push_job(&sh, &sess, &t, true);
                }
            }
        }
    }
    sess.alive.store(false, Ordering::Relaxed);
    sh.sessions.lock().unwrap().retain(|s| s.id != sess.id);
    let logins = sess.st.lock().unwrap().logins.iter().cloned().collect::<Vec<_>>().join(",");
    sh.log(&format!("session {} {} closed ({})", sess.id, sess.peer, logins));
}

fn subscribe(sh: &Shared, sess: &Session, rid: &Value, p: &[Value]) -> Value {
    if sh.current().is_none() {
        return err(rid, 20, "pool has no work from its node yet");
    }
    let mut st = sess.st.lock().unwrap();
    st.subscribed = true;
    st.lock = p.get(1).and_then(|o| o.get("lock")).and_then(|v| v.as_str()).and_then(unhex32);
    ok(rid, json!({"session": format!("{:x}", sess.id), "extranonce1": hex(&st.en1), "protocol": "bound-pool/1",
                   "network": sh.cfg.network}))
}

fn authorize(sh: &Shared, sess: &Session, rid: &Value, p: &[Value]) -> Value {
    let mut st = sess.st.lock().unwrap();
    if !st.subscribed {
        return err(rid, 25, "not subscribed");
    }
    let login = p.first().and_then(|v| v.as_str()).unwrap_or("");
    if valid_login(sh.version, login).is_none() {
        return err(rid, 24, &format!("login is not a valid BOUND {} address (with an optional .worker)", sh.cfg.network));
    }
    if st.logins.len() >= 8 && !st.logins.contains(login) {
        return err(rid, 24, "too many logins in one session");
    }
    st.logins.insert(login.to_string());
    let solo = sess.solo_port || p.get(1).and_then(|v| v.as_str()).is_some_and(|pw| pw.to_ascii_lowercase().contains("solo"));
    if solo {
        st.solo.insert(login.to_string());
    } else {
        st.solo.remove(login);
    }
    drop(st);
    sh.log(&format!("session {} {} authorized {login}{}", sess.id, sess.peer, if solo { " (solo)" } else { "" }));
    ok(rid, json!(true))
}

/// mining.submit [login, job_id, nonce]: nonce as a number (u32), or 8 hex digits of the header's
/// bytes 76..80 (little-endian, as in the header).
fn parse_nonce(v: Option<&Value>) -> Option<u32> {
    match v? {
        Value::Number(n) => n.as_u64().filter(|x| *x <= u32::MAX as u64).map(|x| x as u32),
        Value::String(s) if s.len() == 8 => unhex(s).map(|b| u32::from_le_bytes(b.try_into().unwrap())),
        _ => None,
    }
}

fn submit(sh: &Arc<Shared>, sess: &Session, rid: &Value, p: &[Value], hasher: &mut Option<BoundHasher>) -> Value {
    let login = p.first().and_then(|v| v.as_str()).unwrap_or("").to_string();
    let job_id = p.get(1).and_then(|v| v.as_str()).unwrap_or("").to_string();
    let Some(nonce) = parse_nonce(p.get(2)) else { return err(rid, 20, "bad params: [login, job_id, nonce]") };
    let current = sh.current();
    let solved = *sh.solved_parent.lock().unwrap();
    // Under the session lock: the checks and the duplicate mark; the hash is computed after.
    let (header, target, tmpl, solo) = {
        let mut st = sess.st.lock().unwrap();
        if !st.subscribed {
            return err(rid, 25, "not subscribed");
        }
        if !st.logins.contains(&login) {
            return err(rid, 24, "login not authorized");
        }
        let now_i = Instant::now();
        if now_i.duration_since(st.second.0) >= Duration::from_secs(1) {
            st.second = (now_i, 0);
        }
        st.second.1 += 1;
        if st.second.1 > MAX_SUBMITS_PER_SEC {
            sess.alive.store(false, Ordering::Relaxed);
            return err(rid, 20, "too many submits");
        }
        let solo = st.solo.contains(&login);
        let Some(job) = st.jobs.iter_mut().rev().find(|j| j.id == job_id) else {
            return err(rid, 21, "job not found");
        };
        if current.as_ref().is_none_or(|c| c.prev != job.tmpl.prev) || solved == Some(job.tmpl.prev) {
            sh.counters.stale.fetch_add(1, Ordering::Relaxed);
            return err(rid, 21, "stale job: the chain has a new block");
        }
        if !job.nonces.insert(nonce) {
            return err(rid, 22, "duplicate share");
        }
        let mut header = job.header;
        header[76..80].copy_from_slice(&nonce.to_le_bytes());
        (header, job.target, job.tmpl.clone(), solo)
    };
    if hasher.as_ref().is_none_or(|h| h.lines() != tmpl.lines) {
        *hasher = Some(BoundHasher::new(tmpl.lines));
    }
    let hash = hasher.as_mut().unwrap().hash(&header);
    if !meets(&hash, &target) {
        sh.counters.rejected.fetch_add(1, Ordering::Relaxed);
        let mut st = sess.st.lock().unwrap();
        st.bad_in_a_row += 1;
        if st.bad_in_a_row > MAX_BAD_IN_A_ROW {
            sess.alive.store(false, Ordering::Relaxed);
        }
        return err(rid, 23, "hash above the share target");
    }
    let block = meets(&hash, &tmpl.target);
    let raw = if block {
        let st = sess.st.lock().unwrap();
        st.jobs.iter().find(|j| j.id == job_id).map(|j| j.block(&header))
    } else {
        None
    };
    credit(sh, &login, solo, &tmpl, &header, &hash, &target, block, raw);
    vardiff(sh, sess);
    ok(rid, json!(true))
}

// ------------------------------------------------------------------------------------- Miningcore-style dialect

/// The shared job for `tmpl`, made once per template.
fn mc_job(sh: &Shared, tmpl: &Arc<Template>) -> Arc<McJob> {
    let mut jobs = sh.mc_jobs.lock().unwrap();
    if let Some(j) = jobs.back().filter(|j| Arc::ptr_eq(&j.tmpl, tmpl)) {
        return j.clone();
    }
    let id = format!("{:x}", sh.next_job.fetch_add(1, Ordering::Relaxed));
    let work = mc::build_work(&tmpl.coinbase_prefix, sh.cfg.tag.as_bytes(), &tmpl.header, &tmpl.wtxids);
    let j = Arc::new(McJob { id, tmpl: tmpl.clone(), work });
    jobs.push_back(j.clone());
    while jobs.len() > KEEP_JOBS {
        jobs.pop_front();
    }
    j
}

/// The k a session of this dialect mines at: its vardiff k, inside the range BoundCuda's difficulty can
/// express exactly, and never a share target harder than the block's.
fn mc_k(k: u32, tmpl: &Template) -> u32 {
    let mut k = k.clamp(mc::K_MIN, mc::K_MAX);
    while k > mc::K_MIN && !meets(&tmpl.target, &mc::target_from_diff(mc::diff_of_k(k))) {
        k -= 1;
    }
    k
}

/// set_difficulty (when it changed), then the shared job.
fn push_job_mc(sh: &Shared, sess: &Session, tmpl: &Arc<Template>, clean: bool) {
    let job = mc_job(sh, tmpl);
    let new_k = {
        let mut st = sess.st.lock().unwrap();
        if st.logins.is_empty() {
            return;
        }
        if clean {
            st.mc_seen.clear();
        }
        let k = mc_k(st.k, tmpl);
        if st.mc_k == Some(k) {
            None
        } else {
            st.mc_prev = st.mc_k.map(|old| (old, Instant::now()));
            st.mc_k = Some(k);
            Some(k)
        }
    };
    if let Some(k) = new_k {
        sess.notify("mining.set_difficulty", json!([mc::diff_of_k(k)]));
    }
    sess.notify("mining.notify", mc::notify_params(&job.id, &job.work, clean));
}

fn subscribe_mc(sh: &Shared, sess: &Session, rid: &Value) -> Value {
    if sh.current().is_none() {
        return err(rid, 20, "pool has no work from its node yet");
    }
    let mut st = sess.st.lock().unwrap();
    st.subscribed = true;
    let sid = format!("{:x}", sess.id);
    ok(rid, json!([[["mining.set_difficulty", sid], ["mining.notify", sid]], hex(&st.en1), mc::EN2_SIZE]))
}

/// mining.submit [login, job_id, extraNonce2, ntime, nonce], each 8 hex digits.
fn submit_mc(sh: &Arc<Shared>, sess: &Session, rid: &Value, p: &[Value], hasher: &mut Option<BoundHasher>) -> Value {
    let s = |i: usize| p.get(i).and_then(|v| v.as_str()).unwrap_or("");
    let login = s(0).to_string();
    let job_id = s(1).to_string();
    let (Some(en2), Some(ntime), Some(nonce)) = (mc::parse_en2(s(2)), mc::parse_hex32(s(3)), mc::parse_hex32(s(4))) else {
        return err(rid, 20, "bad params: [login, job_id, extranonce2, ntime, nonce]");
    };
    let current = sh.current();
    let solved = *sh.solved_parent.lock().unwrap();
    let job = sh.mc_jobs.lock().unwrap().iter().rev().find(|j| j.id == job_id).cloned();
    let (header, coinbase, targets, job, solo) = {
        let mut st = sess.st.lock().unwrap();
        if !st.subscribed {
            return err(rid, 25, "not subscribed");
        }
        if !st.logins.contains(&login) {
            return err(rid, 24, "login not authorized");
        }
        let now_i = Instant::now();
        if now_i.duration_since(st.second.0) >= Duration::from_secs(1) {
            st.second = (now_i, 0);
        }
        st.second.1 += 1;
        if st.second.1 > MAX_SUBMITS_PER_SEC {
            sess.alive.store(false, Ordering::Relaxed);
            return err(rid, 20, "too many submits");
        }
        let solo = st.solo.contains(&login);
        let Some(job) = job else { return err(rid, 21, "job not found") };
        if current.as_ref().is_none_or(|c| c.prev != job.tmpl.prev) || solved == Some(job.tmpl.prev) {
            sh.counters.stale.fetch_add(1, Ordering::Relaxed);
            return err(rid, 21, "stale job: the chain has a new block");
        }
        // The node takes times after the median time past and up to 2 h ahead; keep a margin.
        if (ntime as u64) < job.tmpl.mintime || ntime as u64 > now() + 3600 {
            return err(rid, 20, "ntime out of range");
        }
        if !st.mc_seen.insert((job_id.clone(), en2, ntime, nonce)) {
            return err(rid, 22, "duplicate share");
        }
        let Some(k) = st.mc_k else { return err(rid, 21, "job not found") };
        let mut targets = vec![mc::target_from_diff(mc::diff_of_k(k))];
        if let Some((old, _)) = st.mc_prev.filter(|(_, at)| at.elapsed() < Duration::from_secs(30)) {
            targets.push(mc::target_from_diff(mc::diff_of_k(old)));
        }
        let en1 = st.en1;
        let header = mc::header(&job.work, &en1, &en2, ntime, nonce);
        (header, mc::coinbase(&job.work, &en1, &en2), targets, job, solo)
    };
    if hasher.as_ref().is_none_or(|h| h.lines() != job.tmpl.lines) {
        *hasher = Some(BoundHasher::new(job.tmpl.lines));
    }
    let hash = hasher.as_mut().unwrap().hash(&header);
    // The current difficulty, or the previous one within 30 s of a change (the miner may still be on it).
    let Some(target) = targets.into_iter().find(|t| meets(&hash, t)) else {
        sh.counters.rejected.fetch_add(1, Ordering::Relaxed);
        let mut st = sess.st.lock().unwrap();
        st.bad_in_a_row += 1;
        if st.bad_in_a_row > MAX_BAD_IN_A_ROW {
            sess.alive.store(false, Ordering::Relaxed);
        }
        return err(rid, 23, "low difficulty share");
    };
    let block = meets(&hash, &job.tmpl.target);
    let raw = block.then(|| job.block(&header, &coinbase));
    credit(sh, &login, solo, &job.tmpl, &header, &hash, &target, block, raw);
    vardiff(sh, sess);
    ok(rid, json!(true))
}

/// Counts an accepted share (both dialects alike: shares.jsonl, hash rate, effort) and, if it meets the block
/// target, sends `raw` (the whole block) to the node and records the found/result events.
#[allow(clippy::too_many_arguments)]
fn credit(
    sh: &Arc<Shared>,
    login: &str,
    solo: bool,
    tmpl: &Template,
    header: &[u8; 80],
    hash: &[u8; 32],
    target: &[u8; 32],
    block: bool,
    raw: Option<Vec<u8>>,
) {
    let work = work_of(target);
    let block_work = work_of(&tmpl.target);
    let (addr, worker) = valid_login(sh.version, login).unwrap_or_default();
    sh.counters.accepted.fetch_add(1, Ordering::Relaxed);
    let mode = if solo { "solo" } else { "pplns" };
    sh.record(0, json!({"ts": now(), "addr": addr, "worker": worker, "work": work, "height": tmpl.height,
                        "block": block, "mode": mode}));
    sh.recent.lock().unwrap().push_back((Instant::now(), addr.clone(), worker.clone(), work, solo));
    let effort = {
        let mut rw = sh.round_work.lock().unwrap();
        *rw += work;
        let e = *rw / block_work;
        if block {
            *rw = 0.0;
        }
        e
    };
    if block {
        let mut id = block_id(header);
        id.reverse();
        let id = hex(&id);
        sh.counters.blocks_submitted.fetch_add(1, Ordering::Relaxed);
        sh.log(&format!("BLOCK found by {login} at height {} id {id}", tmpl.height));
        let mut prev = tmpl.prev;
        prev.reverse();
        sh.record(1, json!({"ts": now(), "event": "found", "height": tmpl.height, "id": id, "parent": hex(&prev),
                            "finder": login, "sent": raw.is_some(), "block_work": block_work, "mode": mode,
                            "effort": effort, "hash": to_display(hash),
                            "fee_bp": if solo { sh.solo_fee_bp.load(Ordering::Relaxed) } else { sh.fee_bp.load(Ordering::Relaxed) }}));
        if let Some(raw) = raw {
            let (accepted, tip, reason) = match sh.rpc.call("submitblock", json!([hex(&raw)])) {
                Ok(r) => {
                    let acc = r.get("accepted").and_then(|x| x.as_bool()).unwrap_or(false);
                    let tip = r.get("tip").and_then(|x| x.as_bool()).unwrap_or(false);
                    (acc, tip, format!("{}/{}", r.get("header").and_then(|x| x.as_str()).unwrap_or("?"),
                                       r.get("body").and_then(|x| x.as_str()).unwrap_or("?")))
                }
                Err(e) => (false, false, e),
            };
            if accepted {
                sh.counters.blocks_accepted.fetch_add(1, Ordering::Relaxed);
            }
            if accepted && tip {
                *sh.solved_parent.lock().unwrap() = Some(tmpl.prev);
            }
            sh.log(&format!(
                "node {} block {id} at height {} ({reason}{})",
                if accepted { "ACCEPTED" } else { "refused" },
                tmpl.height,
                if accepted && !tip { ", not the tip" } else { "" }
            ));
            sh.record(1, json!({"ts": now(), "event": "result", "height": tmpl.height, "id": id, "finder": login,
                               "accepted": accepted, "tip": tip, "code": if accepted { 0 } else { 1 }, "reason": reason}));
            sh.refresh_now.store(true, Ordering::Relaxed);
        }
    }
}

fn vardiff(sh: &Shared, sess: &Session) {
    let changed = {
        let mut st = sess.st.lock().unwrap();
        st.bad_in_a_row = 0;
        st.window_count += 1;
        let elapsed = st.window_start.elapsed();
        let mut changed = false;
        if st.window_count > RATE_HIGH * 2 || elapsed >= VARDIFF_WINDOW {
            let scaled = st.window_count as f64 * VARDIFF_WINDOW.as_secs_f64() / elapsed.as_secs_f64().max(1.0);
            let old = st.k;
            if scaled > RATE_HIGH as f64 && st.k < K_MAX {
                // Harder: raise k by log2 of how far above the aim the rate is.
                let steps = ((scaled / 6.0).log2().floor() as u32).clamp(1, K_MAX - st.k);
                st.k += steps;
            } else if scaled < RATE_LOW as f64 && st.k > K_MIN {
                st.k -= 1;
            }
            changed = st.k != old;
            st.window_start = Instant::now();
            st.window_count = 0;
        }
        changed
    };
    if changed {
        if let Some(t) = sh.current() {
            push_job(sh, sess, &t, false);
        }
    }
}

/// Idle sessions also get easier: a miner too slow for its target never submits, so vardiff never
/// runs from submit. Checked every 10 s from the stats loop.
fn vardiff_idle(sh: &Shared) {
    let sessions: Vec<Arc<Session>> = sh.sessions.lock().unwrap().clone();
    for s in sessions {
        let easier = {
            let mut st = s.st.lock().unwrap();
            if st.logins.is_empty() || st.window_start.elapsed() < VARDIFF_WINDOW * 2 || st.window_count > 0 || st.k <= K_MIN {
                false
            } else {
                st.k -= 1;
                st.window_start = Instant::now();
                true
            }
        };
        if easier {
            if let Some(t) = sh.current() {
                push_job(sh, &s, &t, false);
            }
        }
    }
}

// ------------------------------------------------------------------------------------- stats

/// Reads the fees from <data>/pool-config.json: {"fee_percent": 0.0, "solo_fee_percent": 0.0}.
/// A missing file is created with 0 % for both. A broken file or out-of-range value keeps the
/// current fees and is logged, so a typo never changes the fee by accident.
fn load_fees(sh: &Shared) {
    let path = sh.cfg.data.join("pool-config.json");
    if !path.exists() {
        let _ = std::fs::write(&path, "{\n  \"fee_percent\": 0.0,\n  \"solo_fee_percent\": 0.0\n}\n");
    }
    let parsed = std::fs::read_to_string(&path).ok().and_then(|t| serde_json::from_str::<Value>(&t).ok());
    let Some(cfg) = parsed else {
        sh.log("pool-config.json does not parse; fees unchanged");
        return;
    };
    for (key, slot) in [("fee_percent", &sh.fee_bp), ("solo_fee_percent", &sh.solo_fee_bp)] {
        let Some(pct) = cfg.get(key).and_then(|v| v.as_f64()) else { continue };
        if !(0.0..=10.0).contains(&pct) {
            sh.log(&format!("pool-config.json: {key} {pct} outside 0..10 %; unchanged"));
            continue;
        }
        let bp = (pct * 100.0).round() as u32;
        let old = slot.swap(bp, Ordering::Relaxed);
        if old != bp {
            sh.log(&format!("{key} is now {:.2} % (was {:.2} %)", bp as f64 / 100.0, old as f64 / 100.0));
        }
    }
}

fn stats_loop(sh: Arc<Shared>) {
    loop {
        thread::sleep(Duration::from_secs(10));
        load_fees(&sh);
        vardiff_idle(&sh);
        let mut by_addr: HashMap<String, (f64, HashMap<String, f64>, bool)> = HashMap::new();
        let total = {
            let mut recent = sh.recent.lock().unwrap();
            while recent.front().is_some_and(|r| r.0.elapsed() > HASHRATE_WINDOW) {
                recent.pop_front();
            }
            let mut total = 0.0;
            for (_, a, w, work, solo) in recent.iter() {
                total += work;
                let e = by_addr.entry(a.clone()).or_default();
                e.0 += work;
                *e.1.entry(w.clone()).or_default() += work;
                e.2 |= *solo;
            }
            total
        };
        // Until the window has filled, divide by the time the pool has run, not the whole window.
        let secs = HASHRATE_WINDOW.as_secs_f64().min((now() - sh.started).max(10) as f64);
        let t = sh.current();
        let miners: Vec<Value> = by_addr
            .iter()
            .map(|(a, (w, ws, solo))| {
                json!({"addr": a, "hashrate": w / secs, "solo": solo,
                       "workers": ws.iter().map(|(n, x)| json!({"name": n, "hashrate": x / secs})).collect::<Vec<_>>()})
            })
            .collect();
        let peers = sh.peers.load(Ordering::Relaxed);
        let node_up = sh.node_up.load(Ordering::Relaxed);
        let st = json!({
            "updated": now(), "started": sh.started, "name": sh.cfg.name, "network": sh.cfg.network,
            "node_online": node_up, "peer_online": node_up && peers > 0, "peers": peers,
            "sessions": sh.sessions.lock().unwrap().len(),
            "hashrate": total / secs, "unit": "H/s",
            "fee_percent": sh.fee_bp.load(Ordering::Relaxed) as f64 / 100.0,
            "solo_fee_percent": sh.solo_fee_bp.load(Ordering::Relaxed) as f64 / 100.0,
            "height": t.as_ref().map(|t| t.height), "bits": t.as_ref().map(|t| format!("{:08x}", t.bits)),
            "network_work_per_block": t.as_ref().map(|t| work_of(&t.target)),
            "round_effort": t.as_ref().map(|t| *sh.round_work.lock().unwrap() / work_of(&t.target)),
            "accepted": sh.counters.accepted.load(Ordering::Relaxed),
            "rejected": sh.counters.rejected.load(Ordering::Relaxed),
            "stale": sh.counters.stale.load(Ordering::Relaxed),
            "blocks_submitted": sh.counters.blocks_submitted.load(Ordering::Relaxed),
            "blocks_accepted": sh.counters.blocks_accepted.load(Ordering::Relaxed),
            "miners": miners,
            "job_age_s": t.as_ref().map(|t| t.created.elapsed().as_secs()),
        });
        let tmp = sh.cfg.data.join("stats.json.tmp");
        if std::fs::write(&tmp, serde_json::to_vec_pretty(&st).unwrap()).is_ok() {
            let _ = std::fs::rename(&tmp, sh.cfg.data.join("stats.json"));
        }
    }
}

/// The round's work so far, rebuilt from the share log so a restart does not reset the round effort: the work of
/// every share after the last block share (the same rule the live count uses).
fn round_work_from_log(path: &std::path::Path) -> f64 {
    let Ok(f) = File::open(path) else { return 0.0 };
    let mut work = 0.0;
    for line in BufReader::new(f).lines().map_while(Result::ok) {
        let Ok(v) = serde_json::from_str::<Value>(&line) else { continue };
        work += v.get("work").and_then(Value::as_f64).unwrap_or(0.0);
        if v.get("block").and_then(Value::as_bool) == Some(true) {
            work = 0.0;
        }
    }
    work
}

fn main() {
    let cfg = config();
    let version = address_version(&cfg.network).unwrap_or_else(|| panic!("--network mainnet|testnet|regtest"));
    assert!(
        decode_address(&cfg.address, version).is_some(),
        "--address must be a {} address of the pool wallet",
        cfg.network
    );
    assert!(!cfg.cookie.as_os_str().is_empty(), "--cookie <boundd datadir>/.cookie is required");
    std::fs::create_dir_all(&cfg.data).expect("create the data directory");
    let open = |n: &str| OpenOptions::new().create(true).append(true).open(cfg.data.join(n)).expect("open log file");
    let files = (open("shares.jsonl"), open("blocks.jsonl"), open("pool.log"), open("rejects.jsonl"));
    let rpc = Rpc { addr: cfg.rpc.clone(), cookie: cfg.cookie.clone(), timeout: Duration::from_secs(30) };
    let seed = u32::from_le_bytes(block_id(&[now() as u8; 80])[..4].try_into().unwrap()) ^ (now() as u32) ^ std::process::id();
    let sh = Arc::new(Shared {
        version,
        rpc,
        tmpl: Mutex::new(None),
        mc_jobs: Mutex::new(VecDeque::new()),
        sessions: Mutex::new(Vec::new()),
        recent: Mutex::new(VecDeque::new()),
        next_session: AtomicU64::new(1),
        next_job: AtomicU64::new(1),
        next_en1: AtomicU32::new(seed),
        node_up: AtomicBool::new(false),
        peers: AtomicUsize::new(0),
        refresh_now: AtomicBool::new(false),
        solved_parent: Mutex::new(None),
        lock_key: (!cfg.lock_key.as_os_str().is_empty()).then(|| lock_key(&cfg.lock_key).expect("--lock-key")),
        fee_bp: AtomicU32::new(0),
        solo_fee_bp: AtomicU32::new(0),
        round_work: Mutex::new(round_work_from_log(&cfg.data.join("shares.jsonl"))),
        counters: Counters::default(),
        files: Mutex::new(files),
        started: now(),
        cfg,
    });
    load_fees(&sh);
    sh.log(&format!(
        "{} {} starting: network {}, node RPC {}, coinbase pays {}",
        sh.cfg.name,
        env!("CARGO_PKG_VERSION"),
        sh.cfg.network,
        sh.cfg.rpc,
        sh.cfg.address
    ));
    {
        let s = sh.clone();
        thread::spawn(move || node_loop(s));
    }
    {
        let s = sh.clone();
        thread::spawn(move || stats_loop(s));
    }
    let accept = |addr: String, solo: bool, mc_dialect: bool, sh: Arc<Shared>| {
        let listener = TcpListener::bind(&addr).unwrap_or_else(|e| panic!("listen {addr}: {e}"));
        let dialect = if mc_dialect { "Miningcore-style stratum" } else { "stratum (bound-pool/1)" };
        sh.log(&format!("{dialect} listening on {addr} ({})", if solo { "solo" } else { "PPLNS" }));
        for conn in listener.incoming() {
            match conn {
                Ok(s) => {
                    let sh2 = sh.clone();
                    thread::spawn(move || serve_miner(sh2, s, solo, mc_dialect));
                }
                Err(e) => sh.log(&format!("accept failed: {e}")),
            }
        }
    };
    for (addr, solo, mc_dialect) in
        [(sh.cfg.listen_solo.clone(), true, false), (sh.cfg.listen_mc.clone(), false, true), (sh.cfg.listen_mc_solo.clone(), true, true)]
    {
        if addr != "off" {
            let sh2 = sh.clone();
            thread::spawn(move || accept(addr, solo, mc_dialect, sh2));
        }
    }
    accept(sh.cfg.listen.clone(), false, false, sh.clone());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_work_restarts_after_the_last_block() {
        let path = std::env::temp_dir().join(format!("bound-round-work-{}.jsonl", std::process::id()));
        std::fs::write(
            &path,
            concat!(
                "{\"work\":2.0,\"block\":false}\n",
                "{\"work\":3.0,\"block\":true}\n",
                "{\"work\":1.5,\"block\":false}\n",
                "not json\n",
                "{\"work\":4.0,\"block\":false}\n",
            ),
        )
        .unwrap();
        let work = round_work_from_log(&path);
        let _ = std::fs::remove_file(&path);
        assert_eq!(work, 5.5);
        assert_eq!(round_work_from_log(&path), 0.0);
    }
}
