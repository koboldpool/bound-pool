#!/usr/bin/env python3
"""PPLNS payouts for bound-pool: credits mature pool blocks (once, only while on the best chain) over the last
WINDOW x block work of shares, and with --pay sends balances above --min with the node's wallet (sendtoaddress, one
transaction per miner), unlocked for the run from --passphrase-file or BOUND_WALLET_PASSPHRASE. Lost payments are
credited back. Ledger: <data>/payouts.json.
"""
from __future__ import annotations

import argparse
import base64
import json
import os
import sys
import time
import urllib.request
from decimal import Decimal
from pathlib import Path

# Shared ledger helper (lock, dated copy, fsync'd saves, pending-before-send), loaded by path so it also works
# under python3 -I (which leaves the script's folder off sys.path).
import importlib.util as _ilu
_spec = _ilu.spec_from_file_location("kobold_ledger", Path(__file__).resolve().parent / "kobold_ledger.py")
kl = _ilu.module_from_spec(_spec)
_spec.loader.exec_module(kl)

COINBASE_MATURITY = 100
COIN = 100_000_000           # base units per BOUND
# ConsensusParams per network (src/core/params.cpp): (initial subsidy, halving interval, RPC port).
NETWORKS = {
    "mainnet": (50 * COIN, 210_000, 7332),
    "testnet": (5 * COIN, 2_100_000, 18332),
    "regtest": (50 * COIN, 150, 18543),
}
PAYMENT_CONFIRMATIONS = 6     # a payment counts as done this deep in the chain
PAYMENT_LOST_AFTER = 10       # blocks after sending with the tx neither mined nor in the mempool


def rpc(args, method: str, *params):
    cookie = Path(args.cookie).read_text().strip()
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": list(params)}).encode()
    req = urllib.request.Request(args.rpc, data=body, headers={
        "content-type": "application/json",
        "authorization": "Basic " + base64.b64encode(cookie.encode()).decode()})
    with urllib.request.urlopen(req, timeout=60) as r:
        out = json.loads(r.read())
    if out.get("error"):
        raise RuntimeError(f"{method}: {out['error']}")
    return out["result"]


def units(coins: str) -> int:
    """'1.50000000' (the node's format_coins) in base units."""
    return int(Decimal(coins) * COIN)


def pool_reward(args, height: int) -> int:
    """Base units of the block subsidy (block_subsidy); transaction fees stay with the pool as margin."""
    initial, halving, _ = NETWORKS[args.network]
    halvings = height // halving
    return 0 if halvings >= 64 else initial >> halvings


def read_jsonl(path: Path) -> list[dict]:
    if not path.exists():
        return []
    out = []
    for line in path.read_text(encoding="utf-8").splitlines():
        try:
            out.append(json.loads(line))
        except json.JSONDecodeError:
            pass  # a line cut by a crash
    return out


def reconcile(args, ledger: dict, tip: int) -> None:
    """Checks every pending payment with the wallet's gettransaction. One that was neither mined
    nor is waiting in the mempool PAYMENT_LOST_AFTER blocks after it was sent (e.g. a node restart
    dropped its mempool) is marked failed and its amount goes back to the miner's balance."""
    pending = [p for p in ledger["payments"] if p.get("status", "pending") == "pending"]
    if not pending:
        return
    mempool = set(rpc(args, "getrawmempool") or [])
    for p in pending:
        sent = p.setdefault("height_sent", max(0, tip - 200))
        try:
            tx = rpc(args, "gettransaction", p["txid"])
            conf = int(tx.get("confirmations", 0))
        except RuntimeError:
            tx, conf = {}, 0
        if conf > 0:
            p["mined_height"] = tx.get("blockheight", tip - conf + 1)
            if conf >= PAYMENT_CONFIRMATIONS:
                p["status"] = "confirmed"
                print(f"payment {p['txid'][:16]} to {p['addr'][:16]}... confirmed at height {p['mined_height']}")
        elif p["txid"] in mempool:
            continue
        elif tip - sent >= PAYMENT_LOST_AFTER:
            p["status"] = "failed"
            ledger["balances"][p["addr"]] = ledger["balances"].get(p["addr"], 0) + p["amount"]
            ledger["paid"][p["addr"]] = ledger["paid"].get(p["addr"], 0) - p["amount"]
            print(f"PAYMENT LOST: {p['amount'] / COIN:.8f} BOUND to {p['addr']} ({p['txid']}) was never mined; "
                  f"credited back to the balance")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", default="pool-data")
    ap.add_argument("--network", default="mainnet", choices=sorted(NETWORKS))
    ap.add_argument("--rpc", default="", help="node JSON-RPC URL (default: 127.0.0.1 on the network's port)")
    ap.add_argument("--cookie", default="", help="the node's cookie file (default: ~/.bound/<network>/.cookie)")
    ap.add_argument("--fee", type=float, default=0.0,
                    help="fee in percent for old block records that don't carry their own fee_bp")
    ap.add_argument("--window", type=float, default=2.0, help="PPLNS window in block works")
    ap.add_argument("--min", type=float, default=1.0, help="minimum payout in BOUND")
    ap.add_argument("--reserve", type=float, default=0.01, help="BOUND always left in the wallet for fees")
    ap.add_argument("--fee-rate", type=float, default=None, help="units per byte (default: the node's estimate)")
    ap.add_argument("--passphrase-file", default="", help="file whose first line is the wallet passphrase")
    ap.add_argument("--pay", action="store_true", help="actually send payments")
    args = ap.parse_args()
    if not args.rpc:
        args.rpc = f"http://127.0.0.1:{NETWORKS[args.network][2]}/"
    if not args.cookie:
        args.cookie = str(Path.home() / ".bound" / args.network / ".cookie")

    data = Path(args.data)
    ledger_path = data / "payouts.json"
    led = kl.Ledger(ledger_path)  # lock + dated copy before the run
    ledger = led.open({
        "credited": {}, "orphaned": {}, "balances": {}, "paid": {}, "payments": [], "pool_fees": 0})

    def save():
        led.save(ledger)  # temp file, fsync, rename, fsync the folder

    tip = int(rpc(args, "getblockcount"))
    reconcile(args, ledger, tip)
    save()
    events = read_jsonl(data / "blocks.jsonl")
    found = {e["id"]: e for e in events if e.get("event") == "found"}
    accepted = {e["id"] for e in events if e.get("event") == "result" and e.get("accepted")}
    shares = read_jsonl(data / "shares.jsonl")

    for bid, blk in sorted(found.items(), key=lambda kv: kv[1]["height"]):
        if bid in ledger["credited"] or bid in ledger["orphaned"] or bid not in accepted:
            continue
        h = blk["height"]
        if tip - h < COINBASE_MATURITY:
            continue  # not mature yet
        if rpc(args, "getblockhash", h) != bid:
            ledger["orphaned"][bid] = {"height": h, "ts": blk["ts"]}
            print(f"block {h} {bid[:16]} is not on the best chain: orphaned, nothing credited")
            continue
        reward = pool_reward(args, h)
        # The fee in force when the block was found (recorded by the pool); --fee only for old
        # records without it. So a fee change never touches blocks found before it.
        fee_bp = int(blk["fee_bp"]) if "fee_bp" in blk else int(round(args.fee * 100))
        fee = reward * fee_bp // 10_000
        to_split = reward - fee
        mode = blk.get("mode", "pplns")
        work_by: dict[str, float] = {}
        total = 0.0
        if mode == "solo":
            # Solo: the whole block (less the solo fee) goes to the address that found it.
            work_by[blk["finder"].split(".", 1)[0]] = 1.0
            total = 1.0
        else:
            # PPLNS: walk back from the block over pool (non-solo) shares until the window is filled.
            window = args.window * float(blk.get("block_work") or 0)
            for s in reversed(shares):
                if s["ts"] > blk["ts"] or s.get("mode", "pplns") == "solo":
                    continue
                if window and total >= window:
                    break
                work_by[s["addr"]] = work_by.get(s["addr"], 0.0) + s["work"]
                total += s["work"]
        if total <= 0:
            print(f"block {h}: no shares in the window, kept as pool income")
            ledger["pool_fees"] += reward
        else:
            given = 0
            for addr, w in work_by.items():
                part = int(to_split * w / total)
                ledger["balances"][addr] = ledger["balances"].get(addr, 0) + part
                given += part
            ledger["pool_fees"] += reward - given
        ledger["credited"][bid] = {"height": h, "reward": reward, "fee": fee, "fee_bp": fee_bp, "mode": mode,
                                   "miners": len(work_by), "ts": blk["ts"]}
        print(f"block {h} credited ({mode}, fee {fee_bp / 100:.2f} %): {reward / COIN:.8f} BOUND over "
              f"{len(work_by)} miners (fee {fee / COIN:.8f})")
        save()

    due = {a: b for a, b in ledger["balances"].items() if b >= args.min * COIN}
    print(f"tip {tip}; {len(ledger['credited'])} blocks credited; "
          f"{len(due)} balances due (>= {args.min} BOUND); owed in total "
          f"{sum(ledger['balances'].values()) / COIN:.8f} BOUND")
    for a, b in sorted(ledger["balances"].items(), key=lambda kv: -kv[1]):
        print(f"  {a}  {b / COIN:.8f} BOUND{'  (due)' if a in due else ''}")
    if args.pay and kl.hold(ledger, ledger_path):
        save()
        return kl.HOLD_EXIT
    if not args.pay or not due:
        save()
        return 0

    info = rpc(args, "getwalletinfo")
    passphrase = os.environ.get("BOUND_WALLET_PASSPHRASE")
    if args.passphrase_file:
        lines = Path(args.passphrase_file).read_text(encoding="utf-8").splitlines()
        passphrase = lines[0] if lines else None
    unlocked_here = False
    if info.get("locked"):
        if not passphrase:
            print("the pool wallet is locked and no passphrase was given; nothing paid")
            save()
            return 1
        rpc(args, "walletpassphrase", passphrase, 300)
        unlocked_here = True
    try:
        available = units(rpc(args, "getbalance")) - int(args.reserve * COIN)
        for addr, amount in sorted(due.items(), key=lambda kv: -kv[1]):
            # The node's wallet spends its own unconfirmed change, so payments can follow each other.
            if amount > available:
                print(f"wallet has {available / COIN:.8f} BOUND spendable, not enough for {addr}; stopping")
                break
            text = f"{amount / COIN:.8f}"
            params = [addr, text] + ([args.fee_rate] if args.fee_rate is not None else [])
            # Pending before send: recorded and saved first, so a crash after the send cannot pay twice.
            intent = kl.new_intent()
            kl.add_intent(ledger, intent, addr, amount, height_sent=tip)
            save()
            try:
                txid = rpc(args, "sendtoaddress", *params)
            except Exception as e:  # noqa: BLE001
                if not kl.refused(e):
                    raise  # no answer: it may have gone out; stays 'sending', the next run holds
                kl.drop_intent(ledger, intent)
                save()
                print(f"payment to {addr} failed: {e}")
                break
            fee = 0
            try:
                fee = abs(units(rpc(args, "gettransaction", txid).get("fee", "0")))
            except RuntimeError:
                pass
            kl.mark_sent(ledger, intent, txid, fee=fee, height_sent=int(rpc(args, "getblockcount")))
            available -= amount + fee
            save()
            print(f"paid {text} BOUND to {addr}: {txid} (fee {fee / COIN:.8f})")
    finally:
        if unlocked_here:
            rpc(args, "walletlock")
    save()
    return 0


if __name__ == "__main__":
    sys.exit(main())
