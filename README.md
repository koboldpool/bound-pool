# bound-pool

The mining pool software behind [Kobold Pool](https://koboldpool.com/bound/) for **BOUND**, a CPU-mined coin
([github.com/Sonic-Bound/Bound](https://github.com/Sonic-Bound/Bound)), plus the CPU miner that mines on it. Published so
miners can check how their shares are counted and paid.

| Program | What it does |
|---|---|
| `bound-miner` | CPU miner for the pool (Windows and Linux) |
| `bound-pool` | the pool server: stratum `bound-pool/1` (PPLNS port and solo port), work from a patched BOUND node, every share re-hashed |
| `payout.py` | PPLNS payouts with the node's own wallet; tracks every payment until it is deep in the chain |
| `boundhash` | BoundHash from the command line: test vectors, single hashes, a benchmark |
| `node/bound-pool-rpc.patch` | adds `getblocktemplate` and `submitblock` to the BOUND node's RPC (it has neither) |

## Mine on Kobold Pool

Download `bound-miner` from the [releases](https://github.com/koboldpool/bound-pool/releases) (check it against
`SHA256SUMS`), then:

```
bound-miner -o bound.koboldpool.com:3480 -u YOUR_BOUND_ADDRESS.rig1 -t 8
```

Port 3480 is PPLNS, 3490 solo. `-t` is the number of CPU threads. A wallet: the official BOUND release (`bound-qt`).

## How shares and payouts work

- **Work.** The pool asks its node for a block template and gives every connection its own block header (the coinbase
  carries the pool tag, the connection's extranonce and a job counter). The miner only rolls the 32-bit nonce.
- **Share check.** Every submitted share is hashed again with the Rust BoundHash (`src/boundhash.rs`, checked against the
  node's test vectors) and counted only if it meets the connection's target. Duplicates and stale jobs are refused.
- **Difficulty.** Per-connection vardiff aims at 3–12 shares a minute. Shares count by their **work**, not their number.
- **Blocks.** A share that meets the network target goes to the node with `submitblock`; the answer is logged with the
  fee in force when the block was found.
- **PPLNS.** When a block is mature (100 confirmations) and still on the best chain, `payout.py` splits its reward, minus
  that block's fee, over the pool shares in the last 2 × (block work) before it, by their work. Solo-port blocks go whole
  to their finder, minus the solo fee.
- **Payments.** Balances at or above the minimum are paid with the node wallet's `sendtoaddress`, one transaction per
  miner. Each payment is written to the ledger (`<data>/payouts.json`) before the next one, and checked until it is deep
  in the chain; one that disappears is marked failed and credited back. A block is never credited twice.
- **Fees.** `<data>/pool-config.json`, `{"fee_percent": 0.0, "solo_fee_percent": 0.0}`, re-read every 10 s.
- The pool hands out no work while its node is syncing, has no peers, or its tip is older than `--max-tip-age`.

## Build

Rust 1.85 or later:

```
cargo build --release --locked
cargo test --release
./target/release/boundhash --vectors
python3 -m unittest test_payout
```

GitHub Actions (`.github/workflows/build.yml`) does the same on every push, cross-builds the Windows miner, and attaches
the binaries with `SHA256SUMS` to each release (tag `v*`).

## The node

The pool needs a BOUND node with `node/bound-pool-rpc.patch` applied (BOUND v1.1.0):

```
git clone https://github.com/Sonic-Bound/Bound && cd Bound && git checkout v1.1.0
git apply ../node/bound-pool-rpc.patch
docker build -t bound-node-build -f ../node/Dockerfile ../node
docker run --rm -v "$PWD:/src" bound-node-build bash -c \
  'cmake -S /src -B /src/build -G Ninja -DCMAKE_BUILD_TYPE=Release -DBOUND_GUI=OFF && cmake --build /src/build'
```

## Run

1. The patched node: `boundd --mainnet --datadir <node dir> node`. Let it sync.
2. The pool wallet, in that node: `createwallet` (write down the 24 words), then `getnewaddress`. Every block pays this
   address.
3. The pool:

   ```
   bound-pool --network mainnet --address <pool address> --cookie <node dir>/.cookie --data pool-data \
              [--listen 0.0.0.0:3480] [--listen-solo 0.0.0.0:3490]
   ```

4. Payouts every 30 minutes or so; without `--pay` it only reports:

   ```
   python3 payout.py --network mainnet --data pool-data --cookie <node dir>/.cookie \
       --passphrase-file <file with the wallet passphrase> --min 1 --pay
   ```

`deploy/` has example systemd units for all of this.

## License

MIT (`LICENSE`). BoundHash is ported from the BOUND node, also MIT; see `NOTICE`.
