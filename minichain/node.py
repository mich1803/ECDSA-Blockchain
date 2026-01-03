from __future__ import annotations

import argparse
import os
from typing import List, Dict, Any, Optional, Set
import hashlib

import requests
from flask import Flask, request, jsonify

from .chain import Blockchain, ChainConfig
from .models import Transaction, Block, Signature
from .crypto import sign_digest_recoverable, hash_msg, pubkey_from_hex, pubkey_to_address
from .storage import read_json, write_json, ensure_dir
from .utils import Log, utc_ms, canonical_json, short, normalize_hex, is_address


DEFAULT_DATA_DIR = "data"


def load_wallet(path: str) -> Dict[str, str]:
    w = read_json(path)
    if not w:
        raise RuntimeError(f"Wallet not found at {path}. Create one with scripts/create_wallet.py")
    if "private_key_hex" not in w or "public_key_hex" not in w:
        raise RuntimeError("Invalid wallet format")
    return w


def derive_address_from_wallet(wallet: Dict[str, str]) -> str:
    """
    IMPORTANT: address is derived from public key. If wallet["address"] is present but wrong,
    nodes will appear inconsistent. Prefer derived if you suspect mismatch.
    """
    if "address" in wallet and wallet["address"]:
        a = normalize_hex(wallet["address"])
        if is_address(a):
            return a
    pub = pubkey_from_hex(wallet["public_key_hex"])
    return pubkey_to_address(pub.format(compressed=False))


def tx_id(tx_dict: Dict[str, Any]) -> str:
    """
    Stable identifier for dedup.
    Includes signature.
    """
    b = canonical_json(tx_dict)
    return hashlib.sha256(b).hexdigest()


def block_id(block_dict: Dict[str, Any]) -> str:
    """
    Stable identifier for dedup blocks.
    Prefer the block hash if present.
    """
    h = block_dict.get("hash")
    if isinstance(h, str) and len(h) == 64:
        return h
    b = canonical_json(block_dict)
    return hashlib.sha256(b).hexdigest()


def run():
    parser = argparse.ArgumentParser(description="Mini ECDSA Blockchain Node (safe relay + shared genesis alloc)")
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--data-dir", default=DEFAULT_DATA_DIR)
    parser.add_argument("--peers", default="", help="Comma-separated peers, e.g. http://127.0.0.1:5001,http://127.0.0.1:5002")
    parser.add_argument("--difficulty", type=int, default=4)
    parser.add_argument("--wallet", default="wallet.json", help="Path to wallet JSON")
    parser.add_argument("--genesis", default="", help="Path to genesis.json with alloc mapping")
    parser.add_argument("--block-reward", type=int, default=0, help="Optional issuance per block to proposer (toy)")

    # Demo-only faucet (local state only)
    parser.add_argument("--faucet", action="store_true", help="(Single-node demo) seed balance locally (NOT shared)")
    parser.add_argument("--faucet-amount", type=int, default=100, help="Initial faucet amount if --faucet")

    # Networking safety knobs
    parser.add_argument("--no-broadcast", action="store_true", help="Disable relaying to peers")
    parser.add_argument("--relay-limit", type=int, default=1, help="Max hops for relayed messages (default 1)")

    # Dedup knob
    parser.add_argument("--no-dedup", action="store_true", help="Disable seen_txs/seen_blocks dedup (attack demo)")

    # State knob
    parser.add_argument("--reset-state", action="store_true", help="Ignore persisted state_*.json and start from genesis")

    args = parser.parse_args()

    ensure_dir(args.data_dir)

    peers = [p.strip().rstrip("/") for p in args.peers.split(",") if p.strip()]
    cfg = ChainConfig(difficulty=args.difficulty, block_reward=args.block_reward)
    bc = Blockchain(cfg)

    # ---- Load shared genesis allocation ----
    if args.genesis:
        g = read_json(args.genesis)
        if not g or "alloc" not in g or not isinstance(g["alloc"], dict):
            raise RuntimeError("Invalid genesis file. Expected JSON with {\"alloc\": {\"<addr>\": amount, ...}}")
        bc.set_genesis_alloc(g["alloc"])
        bc.reset_state_to_genesis()
        Log.ok(f"Loaded genesis alloc from {args.genesis} (accounts={len(bc.genesis_alloc)})")

    bc.create_genesis()

    wallet = load_wallet(args.wallet)
    my_priv = wallet["private_key_hex"]
    my_pub = wallet["public_key_hex"]
    my_addr = derive_address_from_wallet(wallet)

    # Faucet is local-only
    if args.faucet:
        bc.get_account(my_addr)["balance"] = bc.get_account(my_addr)["balance"] + args.faucet_amount
        Log.warn("Faucet is LOCAL ONLY. For multi-node consistency, use --genesis on all nodes.")
        Log.ok(f"Faucet seeded {args.faucet_amount} to {short(my_addr)}")

    # ---- Load persisted state if exists ----
    state_path = os.path.join(args.data_dir, f"state_{args.port}.json")
    if not args.reset_state:
        state = read_json(state_path)
        if state:
            try:
                chain = state.get("chain", [])
                if chain:
                    bc.chain = [Block.from_dict(b) for b in chain]
                bc.mempool = [Transaction.from_dict(t) for t in state.get("mempool", [])]

                if "genesis_alloc" in state and isinstance(state["genesis_alloc"], dict):
                    bc.set_genesis_alloc(state["genesis_alloc"])

                bc.accounts = {normalize_hex(k): {"balance": int(v["balance"]), "nonce": int(v["nonce"])}
                               for k, v in state.get("accounts", {}).items()}
                Log.ok(f"Loaded state from {state_path} (blocks={len(bc.chain)}, mempool={len(bc.mempool)})")
            except Exception as e:
                Log.warn(f"Failed to load state: {e}")
    else:
        Log.warn("--reset-state used: ignoring persisted state file(s).")

    app = Flask(__name__)

    # ---- In-memory dedup (prevents storms) ----
    seen_txs: Set[str] = set()
    seen_blocks: Set[str] = set()

    def persist():
        write_json(state_path, bc.chain_as_dict())
        write_json(os.path.join(args.data_dir, f"mempool_{args.port}.json"), [t.to_dict() for t in bc.mempool])

    def broadcast(path: str, payload: Dict[str, Any]) -> None:
        """
        Start a relay:
        - attach origin + hop counter
        """
        if args.no_broadcast:
            return

        payload2 = dict(payload)
        payload2["_origin"] = my_addr
        payload2["_hops"] = 0

        for peer in peers:
            url = peer + path
            try:
                requests.post(url, json=payload2, timeout=2.5)
            except Exception:
                pass

    def relay_from_peer(path: str, payload_with_meta: Dict[str, Any]) -> None:
        """
        Relay what we received from a peer, but stop echo loops:
        - do not relay if origin == me
        - stop when hops >= relay_limit
        """
        if args.no_broadcast:
            return

        origin = payload_with_meta.get("_origin")
        hops = int(payload_with_meta.get("_hops", 0))

        if origin == my_addr:
            return
        if hops >= args.relay_limit:
            return

        payload2 = dict(payload_with_meta)
        payload2["_hops"] = hops + 1

        for peer in peers:
            url = peer + path
            try:
                requests.post(url, json=payload2, timeout=2.5)
            except Exception:
                pass

    def fetch_peer_chain() -> Optional[List[Block]]:
        for peer in peers:
            url = peer + "/chain"
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
        acc = bc.get_account(my_addr)
        return jsonify({
            "address": my_addr,
            "public_key_hex": my_pub,
            "peers": peers,
            "difficulty": bc.cfg.difficulty,
            "height": len(bc.chain) - 1,
            "balance": int(acc["balance"]),
            "nonce": int(acc["nonce"]),
            "block_reward": bc.cfg.block_reward,
            "genesis_accounts": len(bc.genesis_alloc),
            "no_broadcast": bool(args.no_broadcast),
            "relay_limit": int(args.relay_limit),
            "no_dedup": bool(args.no_dedup),
            "reset_state": bool(args.reset_state),
        })

    @app.get("/chain")
    def chain():
        return jsonify({"chain": [b.to_dict() for b in bc.chain]})

    @app.get("/state")
    def state_endpoint():
        return jsonify(bc.chain_as_dict())

    @app.get("/balance/<addr>")
    def balance(addr: str):
        a = normalize_hex(addr)
        if not is_address(a):
            return jsonify({"ok": False, "error": "invalid address"}), 400
        return jsonify({"ok": True, "address": a, "balance": bc.balance_of(a)})

    @app.get("/nonce/<addr>")
    def nonce(addr: str):
        a = normalize_hex(addr)
        if not is_address(a):
            return jsonify({"ok": False, "error": "invalid address"}), 400
        return jsonify({"ok": True, "address": a, "nonce": bc.nonce_of(a)})

    @app.post("/tx/new")
    def tx_new():
        data = request.get_json(force=True)

        origin = data.get("_origin")
        data2 = dict(data)
        data2.pop("_origin", None)
        data2.pop("_hops", None)

        # Dedup (optional)
        if not args.no_dedup:
            tid = tx_id(data2)
            if tid in seen_txs:
                return jsonify({"ok": True, "msg": "already seen"}), 200
            seen_txs.add(tid)

        tx = Transaction.from_dict(data2)
        ok, why = bc.add_tx_to_mempool(tx)
        if ok:
            ok_s, sender, _ = bc.recover_sender(tx)
            Log.ok(f"TX accepted {short(sender)} -> {short(normalize_hex(tx.to))} value={tx.value} nonce={tx.nonce}" if ok_s else "TX accepted")
            persist()

            # Relay safely
            if origin is None:
                broadcast("/tx/new", tx.to_dict())
            else:
                relay_from_peer("/tx/new", data)

            return jsonify({"ok": True, "msg": "accepted"}), 200

        Log.warn(f"TX rejected: {why}")
        return jsonify({"ok": False, "error": why}), 400

    @app.post("/block/new")
    def block_new():
        data = request.get_json(force=True)

        origin = data.get("_origin")
        data2 = dict(data)
        data2.pop("_origin", None)
        data2.pop("_hops", None)

        # Dedup (optional)
        if not args.no_dedup:
            bid = block_id(data2)
            if bid in seen_blocks:
                return jsonify({"ok": True, "msg": "already seen"}), 200
            seen_blocks.add(bid)

        blk = Block.from_dict(data2)
        ok, why = bc.add_block(blk)
        if ok:
            Log.ok(f"BLOCK appended idx={blk.index} hash={short(blk.block_hash, 14)} txs={len(blk.transactions)}")
            persist()

            if origin is None:
                broadcast("/block/new", blk.to_dict())
            else:
                relay_from_peer("/block/new", data)

            return jsonify({"ok": True, "msg": "block appended"}), 200

        Log.warn(f"BLOCK rejected: {why}")
        return jsonify({"ok": False, "error": why}), 400

    @app.post("/mine")
    def mine():
        if not bc.mempool:
            return jsonify({"ok": False, "error": "mempool empty"}), 400

        cand = bc.make_candidate_block(proposer=my_addr)
        ok, mined, tries = bc.mine_block(cand)
        if not ok:
            Log.warn(f"Mining failed after tries={tries}. Still computed hash={short(mined.block_hash, 14)}")
            return jsonify({"ok": False, "error": "mining failed", "tries": tries}), 400

        ok2, why = bc.add_block(mined)
        if not ok2:
            return jsonify({"ok": False, "error": f"mined but invalid locally: {why}"}), 400

        Log.ok(f"MINED block idx={mined.index} tries={tries} hash={short(mined.block_hash, 14)} proposer={short(my_addr)}")
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

    @app.post("/local/make_tx")
    def local_make_tx():
        data = request.get_json(force=True)
        to = data.get("to") or data.get("receiver_address")
        if not to:
            return jsonify({"ok": False, "error": "missing 'to' / receiver_address"}), 400
        to = normalize_hex(to)

        value = data.get("value")
        if value is None:
            value = data.get("amount")
        if value is None:
            return jsonify({"ok": False, "error": "missing 'value' / amount"}), 400
        value = int(value)

        if not is_address(to):
            return jsonify({"ok": False, "error": "invalid receiver address (need 40 hex chars)"}), 400

        nonce = bc.nonce_of(my_addr)
        tx = Transaction(
            to=to,
            value=value,
            nonce=nonce,
            timestamp_ms=utc_ms(),
            data="",
            signature=None,
        )
        digest = hash_msg(canonical_json(tx.payload_dict()))
        v, r_hex, s_hex = sign_digest_recoverable(my_priv, digest)
        tx.signature = Signature(v=v, r=r_hex, s=s_hex)

        ok, why = bc.add_tx_to_mempool(tx)
        if not ok:
            return jsonify({"ok": False, "error": why}), 400

        persist()
        broadcast("/tx/new", tx.to_dict())
        Log.ok(f"LOCAL TX {short(my_addr)} -> {short(to)} value={value} nonce={nonce}")
        return jsonify({"ok": True, "tx": tx.to_dict()}), 200

    Log.info(f"Node starting on {args.host}:{args.port}")
    Log.info(f"My address: {my_addr}")
    if args.genesis:
        Log.info(f"Genesis alloc accounts: {len(bc.genesis_alloc)}")
    if peers:
        Log.info(f"Peers: {peers}")

    if args.no_broadcast:
        Log.warn("Broadcast disabled (--no-broadcast).")
    Log.info(f"Relay limit: {args.relay_limit}")
    Log.info(f"Dedup enabled: {not args.no_dedup}")

    app.run(host=args.host, port=args.port, debug=False)
