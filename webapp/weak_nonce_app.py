from __future__ import annotations

import argparse
from typing import Dict, List, Optional, Tuple

import requests
from coincurve import PrivateKey
from flask import Flask, jsonify, render_template, request

from minichain.crypto import hash_msg, pubkey_from_hex, pubkey_to_address
from minichain.models import Transaction
from minichain.paths import resolve_wallet_path, DEFAULT_WALLETS_DIR
from minichain.storage import read_json
from minichain.utils import canonical_json, normalize_hex, is_address, Log

N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141


def modinv(a: int, n: int = N) -> int:
    return pow(a % n, -1, n)


def int_from_digest(digest32: bytes) -> int:
    return int.from_bytes(digest32, "big") % N


def recover_from_reuse(txs: List[Transaction]) -> int:
    if len(txs) != 2:
        raise ValueError("reuse mode needs exactly 2 txs")
    z1, r1, s1 = tx_z_r_s(txs[0])
    z2, r2, s2 = tx_z_r_s(txs[1])
    if r1 != r2:
        raise ValueError("Signatures do not share the same r (nonce not reused).")

    k = ((z1 - z2) * modinv(s1 - s2)) % N
    x = ((s1 * k - z1) * modinv(r1)) % N
    return x


def tx_z_r_s(tx: Transaction):
    if not tx.signature:
        raise ValueError("tx missing signature")
    digest = hash_msg(canonical_json(tx.payload_dict()))
    z = int_from_digest(digest)
    r = int(tx.signature.r, 16) % N
    s = int(tx.signature.s, 16) % N
    return z, r, s


def collect_txs(state: Dict[str, object]) -> List[Dict[str, object]]:
    txs: List[Dict[str, object]] = []
    for blk in state.get("chain", []):
        txs.extend(blk.get("transactions", []))
    txs.extend(state.get("mempool", []))
    return txs


def find_reuse_pair(
    txs: List[Dict[str, object]],
    target_pubkey: Optional[str],
    target_address: Optional[str],
) -> Tuple[Optional[Transaction], Optional[Transaction], List[str]]:
    logs: List[str] = []
    grouped: Dict[Tuple[str, int], Transaction] = {}

    for raw in txs:
        try:
            tx = Transaction.from_dict(raw)
        except Exception:
            continue
        if not tx.signature or not tx.pubkey:
            continue
        pubkey_hex = normalize_hex(tx.pubkey)
        if target_pubkey and normalize_hex(target_pubkey) != pubkey_hex:
            continue
        if target_address:
            addr = pubkey_to_address(pubkey_from_hex(pubkey_hex).format(compressed=False))
            if normalize_hex(addr) != normalize_hex(target_address):
                continue
        z, r, _ = tx_z_r_s(tx)
        key = (pubkey_hex, r)
        if key in grouped:
            logs.append(f"Found reused r={hex(r)} for pubkey {pubkey_hex[:16]}...")
            return grouped[key], tx, logs
        grouped[key] = tx
        logs.append(f"Scanned tx nonce={tx.nonce} r={hex(r)[:12]}... z={hex(z)[:12]}...")
    return None, None, logs


def create_weak_nonce_app(node_url: str, wallet_name: str, wallets_dir: str) -> Flask:
    app = Flask(__name__)
    node_url = node_url.rstrip("/")
    wallet_path = resolve_wallet_path(wallet_name, wallets_dir)
    wallet = read_json(wallet_path)
    if not wallet:
        raise RuntimeError(f"Wallet not found: {wallet_path}")

    sender_addr = normalize_hex(wallet.get("address", ""))
    pubkey = normalize_hex(wallet.get("public_key_hex", ""))
    if not is_address(sender_addr) or not pubkey:
        raise RuntimeError("Wallet missing address or public key")

    app.config["NODE_URL"] = node_url
    app.config["WALLET"] = wallet
    app.config["SENDER_ADDR"] = sender_addr
    app.config["PUBKEY"] = pubkey

    @app.get("/")
    def index():
        return render_template("weak_nonce.html")

    @app.get("/api/info")
    def api_info():
        return jsonify(
            {
                "node_url": app.config["NODE_URL"],
                "address": app.config["SENDER_ADDR"],
                "pubkey": app.config["PUBKEY"],
                "wallet": wallet_name,
            }
        )

    @app.post("/api/recover")
    def api_recover():
        payload = request.get_json(force=True)
        target_pubkey = normalize_hex(payload.get("pubkey", "")) or None
        target_address = normalize_hex(payload.get("address", "")) or None
        if target_address and not is_address(target_address):
            return jsonify({"ok": False, "msg": "invalid target address"}), 400

        try:
            r = requests.get(f"{app.config['NODE_URL']}/chain", timeout=5)
            r.raise_for_status()
            state = r.json()
        except Exception as exc:
            return jsonify({"ok": False, "msg": f"state fetch failed: {exc}"}), 200

        txs = collect_txs(state)
        tx1, tx2, logs = find_reuse_pair(txs, target_pubkey, target_address)
        if not tx1 or not tx2:
            logs.append("No reused nonce pair found yet.")
            return jsonify({"ok": False, "msg": "no reuse pair found", "logs": logs}), 200

        try:
            recovered_int = recover_from_reuse([tx1, tx2])
        except Exception as exc:
            logs.append(f"Recovery failed: {exc}")
            return jsonify({"ok": False, "msg": f"recover failed: {exc}", "logs": logs}), 200

        recovered_hex = hex(recovered_int)
        priv = PrivateKey(recovered_int.to_bytes(32, "big"))
        derived_addr = pubkey_to_address(priv.public_key.format(compressed=False))
        logs.append("Recovered private key from reused nonce.")

        return jsonify(
            {
                "ok": True,
                "recovered_key": recovered_hex,
                "derived_address": derived_addr,
                "logs": logs,
                "txs": [tx1.to_dict(), tx2.to_dict()],
            }
        )

    return app


def main() -> None:
    parser = argparse.ArgumentParser(description="Weak nonce reuse web UI for the minichain demo")
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=8010)
    parser.add_argument("--node-url", required=True, help="Node base URL, e.g. http://127.0.0.1:5001")
    parser.add_argument("--wallet", required=True, help="Wallet filename or path")
    parser.add_argument("--wallets-dir", default=DEFAULT_WALLETS_DIR)
    args = parser.parse_args()

    app = create_weak_nonce_app(args.node_url, args.wallet, args.wallets_dir)
    Log.ok(f"Weak nonce app listening on http://{args.host}:{args.port}")
    app.run(host=args.host, port=args.port, debug=False, use_reloader=False)


if __name__ == "__main__":
    main()
