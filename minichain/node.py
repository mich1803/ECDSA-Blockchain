from __future__ import annotations

import argparse
import os
from typing import List, Dict, Any, Optional, Set
import hashlib

import requests
from flask import Flask, request, jsonify

from .chain import Blockchain, ChainConfig
from .models import Transaction, Block, Signature
from .crypto import sign_digest, hash_msg, pubkey_from_hex, pubkey_to_address
from .storage import read_json, write_json, ensure_dir
from .utils import Log, utc_ms, canonical_json, short, normalize_hex, is_address
from .paths import resolve_wallet_path, DEFAULT_WALLETS_DIR


DEFAULT_DATA_DIR = "data"


def load_wallet(path: str) -> Dict[str, str]:
    w = read_json(path)
    if not w:
        raise RuntimeError(f"Wallet not found at {path}. Create one with scripts/create_wallet.py")
    if "private_key_hex" not in w or "public_key_hex" not in w:
        raise RuntimeError("Invalid wallet format: expected {private_key_hex, public_key_hex, address?}")
    if "address" not in w:
        # derive address from pubkey if missing
        pub = pubkey_from_hex(w["public_key_hex"])
        w["address"] = pubkey_to_address(pub.format(compressed=False))
    return w


def compute_txid(tx: Transaction) -> str:
    b = canonical_json(tx.to_dict())
    return hashlib.sha256(b).hexdigest()


def compute_block_hash(block_dict: Dict[str, Any]) -> str:
    b = canonical_json(block_dict)
    return hashlib.sha256(b).hexdigest()


def run():
    parser = argparse.ArgumentParser(description="Mini ECDSA Blockchain Node (safe relay + shared genesis alloc)")
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--data-dir", default=DEFAULT_DATA_DIR)
    parser.add_argument(
        "--peers",
        default="",
        help="Comma-separated peers, e.g. http://127.0.0.1:5001,http://127.0.0.1:5002",
    )
    parser.add_argument("--difficulty", type=int, default=4)

    parser.add_argument(
        "--wallet",
        default="wallet.json",
        help="Wallet filename or path. If filename only, resolved under --wallets-dir",
    )
    parser.add_argument(
        "--wallets-dir",
        default=DEFAULT_WALLETS_DIR,
        help="Base directory for wallet files",
    )

    parser.add_argument("--genesis", default="", help="Path to genesis.json with alloc mapping")
    parser.add_argument(
        "--block-reward",
        type=int,
        default=ChainConfig().block_reward,
        help="Optional issuance per block to proposer (toy)",
    )

    # Demo-only faucet (local state only)
    parser.add_argument("--faucet", action="store_true", help="(Single-node demo) seed balance locally (NOT shared)")
    parser.add_argument("--faucet-amount", type=int, default=100, help="Initial faucet amount if --faucet")


    args = parser.parse_args()

    # Resolve wallet filename -> wallets/<file> (unless a path was provided)
    if getattr(args, "wallet", None):
        args.wallet = resolve_wallet_path(args.wallet, getattr(args, "wallets_dir", DEFAULT_WALLETS_DIR))

    # ---- Node state dirs ----
    data_dir = os.path.join(args.data_dir, f"node_{args.port}")
    ensure_dir(data_dir)
    chain_path = os.path.join(data_dir, "state.json")

    # ---- Chain init ----
    cfg = ChainConfig(difficulty=args.difficulty, block_reward=args.block_reward)
    bc = Blockchain(cfg)

    # ---- Load persisted state if any ----
    persisted = read_json(chain_path)
    if persisted:
        try:
            # restore alloc + chain + accounts + mempool if present
            if "genesis_alloc" in persisted:
                bc.set_genesis_alloc(persisted.get("genesis_alloc", {}) or {})
                bc.reset_state_to_genesis()

            if "chain" in persisted:
                from .models import Block as BlockModel

                bc.create_genesis()
                # Replace local chain by loading blocks and validating them on fresh state
                blocks = [BlockModel.from_dict(b) for b in persisted["chain"]]
                if len(blocks) >= 1:
                    # rebuild from genesis
                    tmp = Blockchain(cfg)
                    tmp.set_genesis_alloc(bc.genesis_alloc)
                    tmp.reset_state_to_genesis()
                    tmp.create_genesis()
                    ok_all = True
                    reason = "ok"
                    for blk in blocks[1:]:
                        ok, why = tmp.add_block(blk)
                        if not ok:
                            ok_all = False
                            reason = why
                            break
                    if ok_all:
                        bc.chain = tmp.chain
                        bc.accounts = tmp.accounts
                        bc.mempool = []
                        Log.ok(f"Loaded chain from {chain_path} (height={len(bc.chain)-1})")
                    else:
                        Log.warn(f"Persisted chain invalid, starting fresh. Reason: {reason}")
        except Exception as e:
            Log.warn(f"Failed to load persisted state: {e}")

    # ---- Load shared genesis allocation ----
    if args.genesis:
        g = read_json(args.genesis)
        if not g or "alloc" not in g or not isinstance(g["alloc"], dict):
            raise RuntimeError('Invalid genesis file. Expected JSON with {"alloc": {"<addr>": amount, ...}}')
        bc.set_genesis_alloc(g["alloc"])
        bc.reset_state_to_genesis()
        Log.ok(f"Loaded genesis alloc from {args.genesis} (accounts={len(bc.genesis_alloc)})")

    bc.create_genesis()

    # ---- Wallet / identity ----
    wallet = load_wallet(args.wallet)
    my_priv = wallet["private_key_hex"]
    my_pub = normalize_hex(wallet["public_key_hex"])
    my_addr = normalize_hex(wallet["address"])
    Log.ok(f"Node identity address={my_addr}")

    # Optional faucet (LOCAL only)
    if args.faucet:
        acc = bc.get_account(my_addr)
        if int(acc["balance"]) == 0:
            acc["balance"] = int(args.faucet_amount)
            Log.warn(f"FAUCET enabled: seeded local balance={args.faucet_amount} to {my_addr}")
        else:
            Log.info("FAUCET: balance already non-zero; not reseeding")

    app = Flask(__name__)
    peers: List[str] = [p.strip().rstrip("/") for p in args.peers.split(",") if p.strip()]
    seen_txids: Set[str] = set()

    def persist_state() -> None:
        write_json(chain_path, bc.chain_as_dict())

    def broadcast_tx(tx: Transaction) -> None:
        payload = tx.to_dict()
        for p in peers:
            try:
                requests.post(p + "/tx/new", json=payload, timeout=2)
            except Exception:
                pass

    # -------------------- API --------------------

    @app.get("/identity")
    def identity():
        return jsonify({"address": my_addr, "pubkey": my_pub, "height": len(bc.chain) - 1, "peers": peers})

    @app.get("/chain")
    def chain():
        return jsonify(bc.chain_as_dict())

    @app.get("/balance/<addr>")
    def balance(addr: str):
        addr = normalize_hex(addr)
        return jsonify({"address": addr, "balance": bc.balance_of(addr)})

    @app.get("/nonce/<addr>")
    def nonce(addr: str):
        addr = normalize_hex(addr)
        return jsonify({"address": addr, "nonce": bc.nonce_of(addr)})

    @app.post("/tx/new")
    def tx_new():
        tx_dict = request.get_json(force=True)
        tx = Transaction.from_dict(tx_dict)

        txid = compute_txid(tx)
        if txid in seen_txids:
            return jsonify({"ok": True, "msg": "duplicate ignored"}), 200
        seen_txids.add(txid)

        ok, msg = bc.add_tx_to_mempool(tx)
        if ok:
            persist_state()
            broadcast_tx(tx)
            return jsonify({"ok": True, "msg": "accepted"}), 200
        return jsonify({"ok": False, "msg": msg}), 400

    @app.post("/local/make_tx")
    def local_make_tx():
        body = request.get_json(force=True)
        to = normalize_hex(body["to"])
        value = int(body["value"])

        if not is_address(to):
            return jsonify({"ok": False, "msg": "invalid 'to' address"}), 400
        if value <= 0:
            return jsonify({"ok": False, "msg": "value must be >0"}), 400

        nonce_val = bc.nonce_of(my_addr)
        tx = Transaction(
            to=to,
            value=value,
            nonce=nonce_val,
            timestamp_ms=utc_ms(),
            pubkey=my_pub,
            data="",
            signature=None,
        )

        digest = hash_msg(canonical_json(tx.payload_dict()))
        r_hex, s_hex = sign_digest(my_priv, digest)
        tx.signature = Signature(r=r_hex, s=s_hex)

        ok, msg = bc.add_tx_to_mempool(tx)
        if not ok:
            return jsonify({"ok": False, "msg": msg}), 400

        persist_state()
        broadcast_tx(tx)
        return jsonify({"ok": True, "msg": "created", "tx": tx.to_dict()}), 200

    @app.post("/mine")
    def mine():
        blk = bc.make_candidate_block(my_addr)
        ok, mined, tries = bc.mine_block(blk)
        if not ok:
            return jsonify({"ok": False, "msg": f"mining failed after {tries} tries"}), 400

        ok2, why = bc.add_block(mined)
        if not ok2:
            return jsonify({"ok": False, "msg": why}), 400

        persist_state()

        # best-effort propagate
        for p in peers:
            try:
                requests.post(p + "/block/new", json=mined.to_dict(), timeout=2)
            except Exception:
                pass

        return jsonify({"ok": True, "msg": "mined", "block": mined.to_dict()}), 200

    @app.post("/block/new")
    def block_new():
        blk_dict = request.get_json(force=True)
        blk = Block.from_dict(blk_dict)
        ok, why = bc.add_block(blk)
        if ok:
            persist_state()
            return jsonify({"ok": True, "msg": "accepted"}), 200
        return jsonify({"ok": False, "msg": why}), 400

    @app.post("/sync")
    def sync():
        best = None
        best_len = len(bc.chain)

        for p in peers:
            try:
                r = requests.get(p + "/chain", timeout=3)
                if r.status_code != 200:
                    continue
                d = r.json()
                if "chain" not in d:
                    continue
                chain_list = d["chain"]
                if isinstance(chain_list, list) and len(chain_list) > best_len:
                    best = chain_list
                    best_len = len(chain_list)
            except Exception:
                continue

        if not best:
            return jsonify({"ok": True, "msg": "not replaced: not longer"}), 200

        new_blocks = [Block.from_dict(b) for b in best]
        ok, why = bc.replace_chain_if_better(new_blocks)
        if ok:
            persist_state()
            return jsonify({"ok": True, "msg": "replaced"}), 200
        return jsonify({"ok": True, "msg": "not replaced: " + why}), 200

    Log.ok(f"Listening on http://{args.host}:{args.port}")
    app.run(host=args.host, port=args.port, debug=False, use_reloader=False)
