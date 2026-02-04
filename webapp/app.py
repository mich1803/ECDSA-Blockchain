from __future__ import annotations

import argparse
import os

import requests
from coincurve import PublicKey
from flask import Flask, jsonify, request, render_template

from minichain.crypto import sign_digest, hash_msg
from minichain.models import Transaction, Signature
from minichain.paths import resolve_wallet_path, DEFAULT_WALLETS_DIR
from minichain.storage import read_json
from minichain.utils import canonical_json, normalize_hex, utc_ms, is_address, Log


N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141


def modinv(a: int, n: int = N) -> int:
    return pow(a % n, -1, n)


def int_from_digest(digest32: bytes) -> int:
    return int.from_bytes(digest32, "big") % N


def scalar_to_32(x: int) -> bytes:
    return (x % N).to_bytes(32, "big")


def ecdsa_sign_with_k(priv_hex: str, digest32: bytes, k: int):
    z = int_from_digest(digest32)
    x = int(priv_hex, 16) % N
    k = k % N
    if k == 0:
        raise ValueError("k must be non-zero")

    pub_r = PublicKey.from_valid_secret(scalar_to_32(k))
    uncompressed = pub_r.format(compressed=False)
    r = int.from_bytes(uncompressed[1:33], "big") % N
    if r == 0:
        raise ValueError("r == 0, choose a different k")

    s = (modinv(k) * (z + r * x)) % N
    if s == 0:
        raise ValueError("s == 0, choose a different k")

    r_hex = r.to_bytes(32, "big").hex()
    s_hex = s.to_bytes(32, "big").hex()
    return r_hex, s_hex


def create_user_app(node_url: str, wallet_name: str, wallets_dir: str, weak_signer: bool) -> Flask:
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
    app.config["WEAK_SIGNER"] = weak_signer

    @app.get("/")
    def index():
        return render_template("user.html", weak_signer=app.config["WEAK_SIGNER"])

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

    @app.get("/api/mempool")
    def api_mempool():
        try:
            r = requests.get(app.config["NODE_URL"] + "/chain", timeout=5)
            r.raise_for_status()
            data = r.json()
        except Exception as exc:
            return jsonify({"mempool_size": 0, "error": str(exc)}), 200
        mempool = data.get("mempool", [])
        return jsonify({"mempool_size": len(mempool)})

    @app.post("/api/tx")
    def api_send_tx():
        payload = request.get_json(force=True)
        to_addr = normalize_hex(payload.get("to", ""))
        amount = int(payload.get("amount", 0))
        if not is_address(to_addr):
            return jsonify({"ok": False, "msg": "invalid recipient address"}), 400
        if amount <= 0:
            return jsonify({"ok": False, "msg": "amount must be > 0"}), 400

        try:
            r = requests.get(f"{app.config['NODE_URL']}/nonce/{sender_addr}", timeout=5)
            r.raise_for_status()
            nonce = int(r.json()["nonce"])
        except Exception as exc:
            return jsonify({"ok": False, "msg": f"failed to fetch nonce: {exc}"}), 400

        tx = Transaction(
            to=to_addr,
            value=amount,
            nonce=nonce,
            timestamp_ms=utc_ms(),
            pubkey=pubkey,
            data="",
            signature=None,
        )

        digest = hash_msg(canonical_json(tx.payload_dict()))
        r_hex, s_hex = sign_digest(wallet["private_key_hex"], digest)
        tx.signature = Signature(r=r_hex, s=s_hex)

        try:
            resp = requests.post(app.config["NODE_URL"] + "/tx/new", json=tx.to_dict(), timeout=5)
            return jsonify({"ok": resp.status_code == 200, "status": resp.status_code, "body": resp.text})
        except Exception as exc:
            return jsonify({"ok": False, "msg": f"tx submit failed: {exc}"}), 400

    @app.post("/api/weak-tx")
    def api_weak_tx():
        if not app.config["WEAK_SIGNER"]:
            return jsonify({"ok": False, "msg": "weak mode disabled"}), 400
        payload = request.get_json(force=True)
        to_addr = normalize_hex(payload.get("to", ""))
        amount = int(payload.get("amount", 0))
        if not is_address(to_addr):
            return jsonify({"ok": False, "msg": "invalid recipient address"}), 400
        if amount <= 0:
            return jsonify({"ok": False, "msg": "amount must be > 0"}), 400

        try:
            r = requests.get(f"{app.config['NODE_URL']}/nonce/{sender_addr}", timeout=5)
            r.raise_for_status()
            nonce = int(r.json()["nonce"])
        except Exception as exc:
            return jsonify({"ok": False, "msg": f"failed to fetch nonce: {exc}"}), 400

        k0 = int_from_digest(os.urandom(32))
        txs = []
        results = []

        tx1 = Transaction(
            to=to_addr,
            value=amount,
            nonce=nonce,
            timestamp_ms=utc_ms(),
            pubkey=pubkey,
            data="",
            signature=None,
        )
        digest1 = hash_msg(canonical_json(tx1.payload_dict()))
        try:
            r_hex, s_hex = ecdsa_sign_with_k(wallet["private_key_hex"], digest1, k0)
        except Exception as exc:
            return jsonify({"ok": False, "msg": f"signing failed: {exc}"}), 400
        tx1.signature = Signature(r=r_hex, s=s_hex)
        try:
            resp = requests.post(app.config["NODE_URL"] + "/tx/new", json=tx1.to_dict(), timeout=5)
            results.append({"status": resp.status_code, "body": resp.text})
        except Exception as exc:
            return jsonify({"ok": False, "msg": f"submit failed: {exc}"}), 400
        txs.append(tx1.to_dict())

        try:
            mine_resp = requests.post(app.config["NODE_URL"] + "/mine", json={}, timeout=30)
            results.append({"status": mine_resp.status_code, "body": mine_resp.text})
        except Exception as exc:
            return jsonify({"ok": False, "msg": f"mining failed: {exc}"}), 400

        try:
            r = requests.get(f"{app.config['NODE_URL']}/nonce/{sender_addr}", timeout=5)
            r.raise_for_status()
            nonce2 = int(r.json()["nonce"])
        except Exception as exc:
            return jsonify({"ok": False, "msg": f"failed to fetch nonce after mining: {exc}"}), 400

        tx2 = Transaction(
            to=to_addr,
            value=amount,
            nonce=nonce2,
            timestamp_ms=utc_ms(),
            pubkey=pubkey,
            data="",
            signature=None,
        )
        digest2 = hash_msg(canonical_json(tx2.payload_dict()))
        try:
            r_hex, s_hex = ecdsa_sign_with_k(wallet["private_key_hex"], digest2, k0)
        except Exception as exc:
            return jsonify({"ok": False, "msg": f"signing failed: {exc}"}), 400
        tx2.signature = Signature(r=r_hex, s=s_hex)
        try:
            resp = requests.post(app.config["NODE_URL"] + "/tx/new", json=tx2.to_dict(), timeout=5)
            results.append({"status": resp.status_code, "body": resp.text})
        except Exception as exc:
            return jsonify({"ok": False, "msg": f"submit failed: {exc}"}), 400
        txs.append(tx2.to_dict())

        return jsonify({"ok": True, "results": results, "txs": txs})

    @app.post("/api/mine")
    def api_mine():
        try:
            resp = requests.post(app.config["NODE_URL"] + "/mine", json={}, timeout=30)
            return jsonify({"ok": resp.status_code == 200, "status": resp.status_code, "body": resp.text})
        except Exception as exc:
            return jsonify({"ok": False, "msg": f"mining failed: {exc}"}), 400

    @app.get("/api/balance")
    def api_balance():
        try:
            r = requests.get(f"{app.config['NODE_URL']}/balance/{sender_addr}", timeout=5)
            r.raise_for_status()
            return jsonify(r.json())
        except Exception as exc:
            return jsonify({"ok": False, "msg": f"balance fetch failed: {exc}"}), 400

    @app.get("/api/state")
    def api_state():
        try:
            r = requests.get(f"{app.config['NODE_URL']}/chain", timeout=5)
            r.raise_for_status()
            return jsonify({"ok": True, "state": r.json()})
        except Exception as exc:
            return jsonify({"ok": False, "msg": f"state fetch failed: {exc}"}), 200

    return app


def main() -> None:
    parser = argparse.ArgumentParser(description="Web UI for the minichain demo")
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=8000)
    parser.add_argument("--node-url", required=True, help="Node base URL, e.g. http://127.0.0.1:5001")
    parser.add_argument("--wallet", required=True, help="Wallet filename or path")
    parser.add_argument("--wallets-dir", default=DEFAULT_WALLETS_DIR)
    parser.add_argument("--weak-signer", action="store_true", help="Enable weak nonce demo signing in the UI")
    args = parser.parse_args()

    app = create_user_app(args.node_url, args.wallet, args.wallets_dir, args.weak_signer)
    Log.ok(f"Web app listening on http://{args.host}:{args.port}")
    app.run(host=args.host, port=args.port, debug=False, use_reloader=False)


if __name__ == "__main__":
    main()
