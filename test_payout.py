"""Exact checks of payout.py (BOUND): per-block fees, solo blocks, PPLNS without solo shares, orphans
and refused blocks (from neb-pool's test_payout.py), plus BOUND's wallet path: a locked wallet pays
nothing, payments are recorded, confirmed, and a lost one is credited back. A fake node answers the
RPC calls.

    python -m unittest test_payout
"""
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import payout

REWARD = 5_000_000_000  # 50 BOUND, mainnet heights below the first halving


class FakeNode:
    def __init__(self, tip, chain):
        self.tip, self.chain = tip, chain  # chain: height -> block id on the best chain
        self.locked, self.balance, self.sent, self.mempool, self.txs = True, "0.00000000", [], [], {}

    def rpc(self, args, method, *params):
        if method == "getblockcount":
            return self.tip
        if method == "getblockhash":
            return self.chain.get(params[0], "f" * 64)
        if method == "getrawmempool":
            return list(self.mempool)
        if method == "getwalletinfo":
            return {"locked": self.locked}
        if method == "walletpassphrase":
            assert params[0] == "unit-test-only"
            self.locked = False
            return None
        if method == "walletlock":
            self.locked = True
            return None
        if method == "getbalance":
            return self.balance
        if method == "sendtoaddress":
            assert not self.locked
            txid = f"{len(self.sent) + 1:064x}"
            self.sent.append((params[0], params[1], txid))
            self.mempool.append(txid)
            self.txs[txid] = {"confirmations": 0, "fee": "0.00000190"}
            return txid
        if method == "gettransaction":
            if params[0] not in self.txs:
                raise RuntimeError("not a wallet transaction")
            return self.txs[params[0]]
        raise AssertionError(f"unexpected RPC {method}")


def run_payout(data: Path, *extra, code=0):
    argv = ["payout.py", "--data", str(data), "--window", "2", "--network", "mainnet", "--cookie", "x", *extra]
    with mock.patch.object(sys, "argv", argv):
        assert payout.main() == code
    return json.loads((data / "payouts.json").read_text())


class PayoutTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        d = self.data = Path(self.tmp.name)
        found = lambda bid, h, ts, finder, **kw: {"event": "found", "id": bid, "height": h, "ts": ts,
                                                  "finder": finder, "block_work": 1000.0, **kw}
        result = lambda bid, ok=True: {"event": "result", "id": bid, "accepted": ok}
        blocks = [
            found("a" * 64, 10, 1000, "alice.rig", mode="pplns", fee_bp=0), result("a" * 64),
            found("b" * 64, 20, 2000, "carol.gpu", mode="pplns", fee_bp=200), result("b" * 64),
            found("c" * 64, 25, 2500, "bob.solo1", mode="solo", fee_bp=150), result("c" * 64),
            found("d" * 64, 30, 3000, "alice.rig"), result("d" * 64),  # old record: no mode/fee_bp
            found("e" * 64, 40, 3500, "alice.rig", mode="pplns", fee_bp=200), result("e" * 64),  # orphaned
            found("9" * 64, 45, 3600, "carol.gpu", mode="pplns", fee_bp=200), result("9" * 64, False),  # refused
        ]
        (d / "blocks.jsonl").write_text("\n".join(json.dumps(b) for b in blocks) + "\n")
        sh = lambda ts, addr, work, mode="pplns": {"ts": ts, "addr": addr, "worker": "w", "work": work, "mode": mode}
        shares = [sh(900, "alice", 300), sh(950, "carol", 100), sh(1900, "bob", 1000, "solo"),
                  sh(1900, "alice", 100), sh(1950, "carol", 300)]
        (d / "shares.jsonl").write_text("\n".join(json.dumps(s) for s in shares) + "\n")
        chain = {10: "a" * 64, 20: "b" * 64, 25: "c" * 64, 30: "d" * 64, 40: "0" * 64, 45: "9" * 64}
        self.node = FakeNode(200, chain)
        self.patch = mock.patch.object(payout, "rpc", self.node.rpc)
        self.patch.start()

    def tearDown(self):
        self.patch.stop()
        self.tmp.cleanup()

    def test_per_block_fees_solo_and_pplns(self):
        led = run_payout(self.data, "--fee", "1.0")
        cr = led["credited"]
        self.assertEqual(cr["a" * 64]["fee"], 0)                      # 0 % when found
        self.assertEqual(cr["b" * 64]["fee"], REWARD * 200 // 10_000)  # 2 % when found
        self.assertEqual(cr["c" * 64]["fee"], REWARD * 150 // 10_000)  # solo 1.5 %
        self.assertEqual(cr["d" * 64]["fee"], REWARD * 100 // 10_000)  # old record: --fee 1.0
        self.assertEqual(cr["c" * 64]["mode"], "solo")
        self.assertIn("e" * 64, led["orphaned"])
        self.assertNotIn("9" * 64, cr)                                 # refused by the node
        b = led["balances"]
        # a: 0 % over alice 300 / carol 100. b and d: alice 400 / carol 400 (bob's solo share excluded).
        half_b, half_d = (REWARD - REWARD * 2 // 100) // 2, (REWARD - REWARD // 100) // 2
        self.assertEqual(b["alice"], REWARD * 3 // 4 + half_b + half_d)
        self.assertEqual(b["carol"], REWARD // 4 + half_b + half_d)
        self.assertEqual(b["bob"], REWARD - REWARD * 150 // 10_000)    # the whole solo block, less 1.5 %
        # Every credited base unit is accounted for: balances + fees = rewards.
        self.assertEqual(sum(b.values()) + led["pool_fees"], 4 * REWARD)

    def test_fee_change_later_does_not_touch_credited_blocks(self):
        first = run_payout(self.data, "--fee", "1.0")
        second = run_payout(self.data, "--fee", "5.0")
        self.assertEqual(first["balances"], second["balances"])
        self.assertEqual(first["credited"], second["credited"])

    def test_immature_blocks_wait(self):
        self.node.tip = 115  # 100 confirmations reached for heights <= 15 only
        led = run_payout(self.data)
        self.assertEqual(set(led["credited"]), {"a" * 64})

    def test_halving(self):
        self.assertEqual(payout.pool_reward(mock.Mock(network="mainnet"), 209_999), 50 * payout.COIN)
        self.assertEqual(payout.pool_reward(mock.Mock(network="mainnet"), 210_000), 25 * payout.COIN)
        self.assertEqual(payout.pool_reward(mock.Mock(network="testnet"), 5), 5 * payout.COIN)
        self.assertEqual(payout.pool_reward(mock.Mock(network="regtest"), 150), 25 * payout.COIN)

    def test_locked_wallet_pays_nothing(self):
        self.node.balance = "1000.00000000"
        with mock.patch.dict("os.environ", {}, clear=True):
            led = run_payout(self.data, "--pay", code=1)
        self.assertEqual(self.node.sent, [])
        self.assertEqual(led["payments"], [])

    def test_passphrase_file(self):
        self.node.balance = "1000.00000000"
        pw = self.data / "pass"
        pw.write_text("unit-test-only" + chr(10))
        with mock.patch.dict("os.environ", {}, clear=True):
            led = run_payout(self.data, "--pay", "--passphrase-file", str(pw))
        self.assertEqual(len(self.node.sent), 3)
        self.assertTrue(self.node.locked)
        self.assertEqual(len(led["payments"]), 3)

    def test_pay_confirm_and_lost(self):
        self.node.balance = "1000.00000000"
        with mock.patch.dict("os.environ", {"BOUND_WALLET_PASSPHRASE": "unit-test-only"}):
            led = run_payout(self.data, "--pay")
        self.assertTrue(self.node.locked)  # locked again after the run
        self.assertEqual(len(self.node.sent), 3)
        self.assertEqual(sum(led["balances"].values()), 0)
        self.assertEqual({p["status"] for p in led["payments"]}, {"pending"})
        self.assertEqual(led["payments"][0]["fee"], 190)
        paid_alice = led["paid"]["alice"]
        # Alice's payment is mined 6 deep; bob's vanished (not mined, not in the mempool) 10 blocks on.
        by_addr = {a: t for a, _, t in self.node.sent}
        self.node.txs[by_addr["alice"]] = {"confirmations": 6, "blockheight": 201}
        self.node.mempool = [by_addr["carol"]]
        del self.node.txs[by_addr["bob"]]
        self.node.tip = 210
        led = run_payout(self.data)
        st = {p["addr"]: p["status"] for p in led["payments"]}
        self.assertEqual(st, {"alice": "confirmed", "bob": "failed", "carol": "pending"})
        self.assertEqual(led["paid"]["alice"], paid_alice)
        self.assertEqual(led["paid"]["bob"], 0)
        self.assertEqual(led["balances"]["bob"], REWARD - REWARD * 150 // 10_000)


if __name__ == "__main__":
    unittest.main()
