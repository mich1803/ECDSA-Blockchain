from __future__ import annotations

import argparse
import random
from typing import Dict, List

import requests
from coincurve import PrivateKey, PublicKey
from flask import Flask, jsonify, render_template, request

from minichain.crypto import hash_msg, pubkey_from_hex, pubkey_to_address
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


def fetch_nonce(node: str, addr: str) -> int:
    r = requests.get(node.rstrip("/") + f"/nonce/{addr}", timeout=5)
    r.raise_for_status()
    return int(r.json()["nonce"])


def send_tx(node: str, tx: Transaction):
    r = requests.post(node.rstrip("/") + "/tx/new", json=tx.to_dict(), timeout=10)
    return r.status_code, r.text


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

    @app.post("/api/weak-nonce")
    def api_weak_nonce():
        payload = request.get_json(force=True)
        to_addr = normalize_hex(payload.get("to", ""))
        amount = int(payload.get("amount", 0))
        if not is_address(to_addr):
            return jsonify({"ok": False, "msg": "invalid recipient address"}), 400
        if amount <= 0:
            return jsonify({"ok": False, "msg": "amount must be > 0"}), 400

        k0 = random.randrange(1, N)
        results: List[Dict[str, str]] = []
        txs: List[Transaction] = []

        for i in range(2):
            try:
                account_nonce = fetch_nonce(app.config["NODE_URL"], sender_addr)
            except Exception as exc:
                return jsonify({"ok": False, "msg": f"failed to fetch nonce: {exc}"}), 400

            tx = Transaction(
                to=to_addr,
                value=int(amount),
                nonce=int(account_nonce),
                timestamp_ms=utc_ms(),
                pubkey=normalize_hex(wallet["public_key_hex"]),
                data="",
                signature=None,
            )
            digest = hash_msg(canonical_json(tx.payload_dict()))
            try:
                r_hex, s_hex = ecdsa_sign_with_k(wallet["private_key_hex"], digest, k0)
            except Exception as exc:
                return jsonify({"ok": False, "msg": f"signing failed: {exc}"}), 400
            tx.signature = Signature(r=r_hex, s=s_hex)

            sc, txt = send_tx(app.config["NODE_URL"], tx)
            results.append({"status": str(sc), "body": txt})
            txs.append(tx)

        try:
            recovered_int = recover_from_reuse(txs)
        except Exception as exc:
            return jsonify({"ok": False, "msg": f"recover failed: {exc}"}), 200

        recovered_hex = hex(recovered_int)
        priv = PrivateKey(recovered_int.to_bytes(32, "big"))
        derived_addr = pubkey_to_address(priv.public_key.format(compressed=False))

        return jsonify(
            {
                "ok": True,
                "results": results,
                "recovered_key": recovered_hex,
                "derived_address": derived_addr,
                "txs": [tx.to_dict() for tx in txs],
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
