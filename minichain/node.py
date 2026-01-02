from __future__ import annotations
import argparse
import json
import os
from typing import List, Dict, Any, Optional

import requests
from flask import Flask, request, jsonify

from .chain import Blockchain, ChainConfig
from .models import Transaction, Block, Signature
from .crypto import generate_keypair, sign_digest, hash_msg
from .storage import read_json, write_json, ensure_dir
from .utils import Log, utc_ms, canonical_json, short


DEFAULT_DATA_DIR = "data"


def load_wallet(path: str) -> Dict[str, str]:
    w = read_json(path)
    if not w:
        raise RuntimeError(f"Wallet not found at {path}. Create one with scripts/create_wallet.py")
    if "private_key_hex" not in w or "public_key_hex" not in w:
        raise RuntimeError("Invalid wallet format")
    return w


def run():
    parser = argparse.ArgumentParser(description="Mini ECDSA Blockchain Node (secp256k1)")
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--data-dir", default=DEFAULT_DATA_DIR)
    parser.add_argument("--peers", default="", help="Comma-separated peers, e.g. http://192.168.1.10:5001,http://192.168.1.11:5002")
    parser.add_argument("--difficulty", type=int, default=4)
    parser.add_argument("--wallet", default="wallet.json", help="Path to wallet JSON (private/public keys)")
    parser.add_argument("--faucet", action="store_true", help="If set, seed initial balance to this node pubkey")
    parser.add_argument("--faucet-amount", type=int, default=100, help="Initial faucet amount if --faucet")
    args = parser.parse_args()

    ensure_dir(args.data_dir)

    peers = [p.strip() for p in args.peers.split(",") if p.strip()]
    cfg = ChainConfig(difficulty=args.difficulty)
    bc = Blockchain(cfg)
    bc.create_genesis()

    wallet = load_wallet(args.wallet)
    my_pub = wallet["public_key_hex"]
    my_priv = wallet["private_key_hex"]

    # Faucet initialization (for demo)
    if args.faucet:
        bc.balances[my_pub] = bc.balances.get(my_pub, 0) + args.faucet_amount
        Log.ok(f"Faucet enabled: seeded {args.faucet_amount} coins to {short(my_pub)}")

    # Load persisted state if exists
    chain_path = os.path.join(args.data_dir, f"chain_{args.port}.json")
    state = read_json(chain_path)
    if state and "chain" in state:
        try:
            loaded_chain = [Block.from_dict(b) for b in state["chain"]]
            if loaded_chain:
                bc.chain = loaded_chain
            bc.mempool = [Transaction.from_dict(t) for t in state.get("mempool", [])]
            bc.balances = {k: int(v) for k, v in state.get("balances", {}).items()}
            bc.last_nonce_by_sender = {k: int(v) for k, v in state.get("last_nonce_by_sender", {}).items()}
            Log.ok(f"Loaded state from {chain_path} (blocks={len(bc.chain)}, mempool={len(bc.mempool)})")
        except Exception as e:
            Log.warn(f"Failed to load state: {e}")

    app = Flask(__name__)

    def persist():
        write_json(chain_path, bc.chain_as_dict())
        # also write compact artifacts for presentation
        write_json(os.path.join(args.data_dir, f"mempool_{args.port}.json"), [t.to_dict() for t in bc.mempool])

    def broadcast(path: str, payload: Dict[str, Any]) -> None:
        for peer in peers:
            url = peer.rstrip("/") + path
            try:
                requests.post(url, json=payload, timeout=2.5)
            except Exception:
                pass

    def fetch_peer_chain() -> Optional[List[Block]]:
        for peer in peers:
            url = peer.rstrip("/") + "/chain"
            try:
                r = requests.get(url, timeout=3.0)
                if r.status_code == 200:
                    data = r.json()
                    chain = [Block.from_dict(b) for b in data.get("chain", [])]
                    if chain:
                        return chain
            except Exception:
                continue
        return None

    # --------------------- Endpoints ---------------------

    @app.get("/health")
    def health():
        return jsonify({"ok": True, "port": args.port})

    @app.get("/identity")
    def identity():
        return jsonify({
            "public_key_hex": my_pub,
            "peers": peers,
            "difficulty": bc.cfg.difficulty,
            "height": len(bc.chain) - 1
        })

    @app.get("/chain")
    def chain():
        return jsonify({"chain": [b.to_dict() for b in bc.chain]})

    @app.get("/state")
    def state():
        return jsonify(bc.chain_as_dict())

    @app.post("/tx/new")
    def tx_new():
        data = request.get_json(force=True)
        tx = Transaction.from_dict(data)
        ok, why = bc.add_tx_to_mempool(tx)
        if ok:
            Log.ok(f"TX accepted from {short(tx.sender_pubkey)} -> {short(tx.receiver_pubkey)} amt={tx.amount} nonce={tx.nonce}")
            persist()
            broadcast("/tx/new", tx.to_dict())
            return jsonify({"ok": True, "msg": "accepted"}), 200
        Log.warn(f"TX rejected: {why}")
        return jsonify({"ok": False, "error": why}), 400

    @app.post("/block/new")
    def block_new():
        data = request.get_json(force=True)
        blk = Block.from_dict(data)
        ok, why = bc.add_block(blk)
        if ok:
            Log.ok(f"BLOCK appended idx={blk.index} hash={short(blk.block_hash, 14)} txs={len(blk.transactions)}")
            persist()
            broadcast("/block/new", blk.to_dict())
            return jsonify({"ok": True, "msg": "block appended"}), 200
        Log.warn(f"BLOCK rejected: {why}")
        return jsonify({"ok": False, "error": why}), 400

    @app.post("/mine")
    def mine():
        """
        Mine one block from mempool (PoW light).
        """
        if not bc.mempool:
            return jsonify({"ok": False, "error": "mempool empty"}), 400

        cand = bc.make_candidate_block()
        ok, mined, tries = bc.mine_block(cand)
        if not ok:
            Log.warn(f"Mining failed after tries={tries}. Still broadcasting candidate hash={short(mined.block_hash, 14)}")
            return jsonify({"ok": False, "error": "mining failed", "tries": tries}), 400

        ok2, why = bc.add_block(mined)
        if not ok2:
            return jsonify({"ok": False, "error": f"mined but invalid locally: {why}"}), 400

        Log.ok(f"MINED block idx={mined.index} tries={tries} hash={short(mined.block_hash, 14)}")
        persist()
        broadcast("/block/new", mined.to_dict())
        return jsonify({"ok": True, "block": mined.to_dict(), "tries": tries}), 200

    @app.post("/sync")
    def sync():
        peer_chain = fetch_peer_chain()
        if not peer_chain:
            return jsonify({"ok": False, "error": "no peer chain available"}), 400
        replaced, why = bc.replace_chain_if_better(peer_chain)
        if replaced:
            Log.ok(f"SYNC: chain replaced (new height={len(bc.chain)-1})")
            persist()
            return jsonify({"ok": True, "msg": "replaced"}), 200
        return jsonify({"ok": True, "msg": f"not replaced: {why}"}), 200

    # --------------------- Local helper route ---------------------
    @app.post("/local/make_tx")
    def local_make_tx():
        """
        Convenience endpoint: create + sign tx locally then broadcast.
        body: {receiver_pubkey, amount}
        """
        data = request.get_json(force=True)
        receiver = data["receiver_pubkey"]
        amount = int(data["amount"])
        sender = my_pub

        nonce = bc.last_nonce_by_sender.get(sender, -1) + 1
        tx = Transaction(
            sender_pubkey=sender,
            receiver_pubkey=receiver,
            amount=amount,
            nonce=nonce,
            timestamp_ms=utc_ms(),
            signature=None
        )
        digest = hash_msg(canonical_json(tx.payload_dict()))
        r_hex, s_hex = sign_digest(my_priv, digest)
        tx.signature = Signature(r=r_hex, s=s_hex)

        ok, why = bc.add_tx_to_mempool(tx)
        if not ok:
            return jsonify({"ok": False, "error": why}), 400

        persist()
        broadcast("/tx/new", tx.to_dict())
        Log.ok(f"LOCAL TX sent -> {short(receiver)} amt={amount} nonce={nonce}")
        return jsonify({"ok": True, "tx": tx.to_dict()}), 200

    Log.info(f"Node starting on {args.host}:{args.port}")
    Log.info(f"My pubkey: {my_pub}")
    if peers:
        Log.info(f"Peers: {peers}")

    app.run(host=args.host, port=args.port, debug=False)
