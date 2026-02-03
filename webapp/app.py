from __future__ import annotations

import argparse

import requests
from flask import Flask, jsonify, request, render_template

from minichain.crypto import sign_digest, hash_msg
from minichain.models import Transaction, Signature
from minichain.paths import resolve_wallet_path, DEFAULT_WALLETS_DIR
from minichain.storage import read_json
from minichain.utils import canonical_json, normalize_hex, utc_ms, is_address, Log


def create_user_app(node_url: str, wallet_name: str, wallets_dir: str) -> Flask:
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
        return render_template("user.html")

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

    return app


def main() -> None:
    parser = argparse.ArgumentParser(description="Web UI for the minichain demo")
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=8000)
    parser.add_argument("--node-url", required=True, help="Node base URL, e.g. http://127.0.0.1:5001")
    parser.add_argument("--wallet", required=True, help="Wallet filename or path")
    parser.add_argument("--wallets-dir", default=DEFAULT_WALLETS_DIR)
    args = parser.parse_args()

    app = create_user_app(args.node_url, args.wallet, args.wallets_dir)
    Log.ok(f"Web app listening on http://{args.host}:{args.port}")
    app.run(host=args.host, port=args.port, debug=False, use_reloader=False)


if __name__ == "__main__":
    main()
