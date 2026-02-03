from __future__ import annotations

import argparse
import os
from typing import Dict, Any, List

import requests
from flask import Flask, jsonify, request, render_template

from minichain.crypto import generate_keypair, pubkey_from_hex, pubkey_to_address, sign_digest, hash_msg
from minichain.models import Transaction, Signature
from minichain.paths import resolve_wallet_path, DEFAULT_WALLETS_DIR
from minichain.storage import read_json, write_json, ensure_dir
from minichain.utils import canonical_json, normalize_hex, utc_ms, is_address, Log


DATA_DIR = "webapp_data"
REQUESTS_PATH = os.path.join(DATA_DIR, "wallet_requests.json")
SETTINGS_PATH = os.path.join(DATA_DIR, "settings.json")
DEFAULT_SETTINGS = {
    "node_url": "http://127.0.0.1:5001",
    "difficulty": 2,
    "block_reward": 1,
}


def load_settings() -> Dict[str, Any]:
    stored = read_json(SETTINGS_PATH)
    if isinstance(stored, dict):
        merged = dict(DEFAULT_SETTINGS)
        merged.update(stored)
        return merged
    return dict(DEFAULT_SETTINGS)


def save_settings(settings: Dict[str, Any]) -> None:
    ensure_dir(DATA_DIR)
    write_json(SETTINGS_PATH, settings)


def load_requests() -> List[Dict[str, Any]]:
    data = read_json(REQUESTS_PATH)
    if isinstance(data, list):
        return data
    return []


def save_requests(reqs: List[Dict[str, Any]]) -> None:
    ensure_dir(DATA_DIR)
    write_json(REQUESTS_PATH, reqs)


def list_wallets(wallets_dir: str) -> List[Dict[str, str]]:
    if not os.path.isdir(wallets_dir):
        return []
    wallets = []
    for name in sorted(os.listdir(wallets_dir)):
        if not name.endswith(".json"):
            continue
        path = os.path.join(wallets_dir, name)
        data = read_json(path)
        if not data:
            continue
        addr = data.get("address", "")
        wallets.append({"filename": name, "address": addr})
    return wallets


def create_wallet_file(filename: str, wallets_dir: str) -> Dict[str, str]:
    ensure_dir(wallets_dir)
    out_path = resolve_wallet_path(filename, wallets_dir)
    if os.path.exists(out_path):
        raise FileExistsError(f"wallet already exists: {out_path}")
    kp = generate_keypair()
    pub = pubkey_from_hex(kp.public_key_hex)
    addr = pubkey_to_address(pub.format(compressed=False))
    write_json(
        out_path,
        {
            "private_key_hex": kp.private_key_hex,
            "public_key_hex": kp.public_key_hex,
            "address": addr,
        },
    )
    return {"filename": filename, "address": addr, "public_key_hex": kp.public_key_hex}


def get_node_url(payload: Dict[str, Any]) -> str:
    settings = load_settings()
    return str(payload.get("node_url") or settings["node_url"]).rstrip("/")


def create_manager_app() -> Flask:
    app = Flask(__name__)

    @app.get("/")
    def index():
        return render_template("manager.html")

    @app.get("/api/settings")
    def api_settings():
        return jsonify(load_settings())

    @app.post("/api/settings")
    def api_settings_update():
        payload = request.get_json(force=True)
        settings = load_settings()
        for key in ("node_url", "difficulty", "block_reward"):
            if key in payload:
                settings[key] = payload[key]
        save_settings(settings)
        return jsonify({"ok": True, "settings": settings})

    @app.get("/api/wallets")
    def api_wallets():
        wallets_dir = request.args.get("wallets_dir", DEFAULT_WALLETS_DIR)
        return jsonify({"wallets": list_wallets(wallets_dir)})

    @app.post("/api/wallets/request")
    def api_wallet_request():
        payload = request.get_json(force=True)
        name = payload.get("name", "").strip()
        amount = int(payload.get("amount", 0))
        wallets_dir = payload.get("wallets_dir", DEFAULT_WALLETS_DIR)
        if not name:
            existing = {w["filename"] for w in list_wallets(wallets_dir)}
            idx = 1
            while True:
                candidate = f"wallet_{idx}.json"
                if candidate not in existing:
                    name = candidate
                    break
                idx += 1
        if not name.endswith(".json"):
            name = f"{name}.json"
        if not name:
            return jsonify({"ok": False, "msg": "missing wallet name"}), 400
        if amount < 0:
            return jsonify({"ok": False, "msg": "amount must be >= 0"}), 400
        try:
            info = create_wallet_file(name, wallets_dir)
        except FileExistsError as exc:
            return jsonify({"ok": False, "msg": str(exc)}), 400
        reqs = load_requests()
        reqs.append(
            {
                "filename": info["filename"],
                "address": info["address"],
                "public_key_hex": info["public_key_hex"],
                "amount": amount,
            }
        )
        save_requests(reqs)
        return jsonify({"ok": True, "wallet": info, "requested_amount": amount})

    @app.get("/api/wallet-requests")
    def api_wallet_requests():
        return jsonify({"requests": load_requests()})

    @app.post("/api/genesis")
    def api_create_genesis():
        payload = request.get_json(force=True)
        genesis_path = payload.get("genesis_path", "genesis.json")
        reqs = load_requests()
        if not reqs:
            return jsonify({"ok": False, "msg": "no wallet requests found"}), 400
        alloc: Dict[str, int] = {}
        for req in reqs:
            addr = normalize_hex(req["address"])
            if not is_address(addr):
                return jsonify({"ok": False, "msg": f"invalid address in requests: {addr}"}), 400
            alloc[addr] = int(req["amount"])
        write_json(genesis_path, {"alloc": alloc})
        return jsonify({"ok": True, "genesis_path": genesis_path, "accounts": len(alloc)})

    @app.get("/api/mempool")
    def api_mempool():
        node_url = get_node_url(request.args)
        try:
            r = requests.get(node_url + "/chain", timeout=5)
            r.raise_for_status()
            data = r.json()
        except Exception as exc:
            return jsonify({"mempool_size": 0, "error": str(exc)}), 200
        mempool = data.get("mempool", [])
        return jsonify({"mempool_size": len(mempool)})

    @app.post("/api/mine")
    def api_mine():
        node_url = get_node_url(request.get_json(force=True))
        try:
            resp = requests.post(node_url + "/mine", json={}, timeout=30)
            return jsonify({"ok": resp.status_code == 200, "status": resp.status_code, "body": resp.text})
        except Exception as exc:
            return jsonify({"ok": False, "msg": f"mining failed: {exc}"}), 400

    @app.get("/api/balance")
    def api_balance():
        addr = normalize_hex(request.args.get("address", ""))
        node_url = get_node_url(request.args)
        if not is_address(addr):
            return jsonify({"ok": False, "msg": "invalid address"}), 400
        try:
            r = requests.get(f"{node_url}/balance/{addr}", timeout=5)
            r.raise_for_status()
            return jsonify(r.json())
        except Exception as exc:
            return jsonify({"ok": False, "msg": f"balance fetch failed: {exc}"}), 400

    @app.get("/api/accounts")
    def api_accounts():
        node_url = get_node_url(request.args)
        wallets_dir = request.args.get("wallets_dir", DEFAULT_WALLETS_DIR)
        wallets = list_wallets(wallets_dir)
        balances = []
        for w in wallets:
            addr = normalize_hex(w["address"])
            if not is_address(addr):
                continue
            try:
                r = requests.get(f"{node_url}/balance/{addr}", timeout=5)
                if r.status_code == 200:
                    balances.append({"address": addr, "balance": r.json()["balance"], "wallet": w["filename"]})
            except Exception:
                continue
        return jsonify({"accounts": balances})

    @app.get("/api/chain")
    def api_chain():
        node_url = get_node_url(request.args)
        try:
            r = requests.get(node_url + "/chain", timeout=5)
            r.raise_for_status()
            return jsonify(r.json())
        except Exception as exc:
            return jsonify({"ok": False, "msg": f"chain fetch failed: {exc}"}), 400

    @app.get("/api/logs")
    def api_logs():
        node_url = get_node_url(request.args)
        try:
            r = requests.get(node_url + "/chain", timeout=5)
            r.raise_for_status()
            chain = r.json().get("chain", [])
        except Exception as exc:
            return jsonify({"transactions": [], "error": str(exc)}), 200
        txs = []
        for blk in chain:
            for tx in blk.get("transactions", []):
                sender_addr = ""
                pub_hex = tx.get("pubkey", "")
                if pub_hex:
                    try:
                        pub = pubkey_from_hex(pub_hex)
                        sender_addr = pubkey_to_address(pub.format(compressed=False))
                    except Exception:
                        sender_addr = ""
                txs.append(
                    {
                        "block": blk.get("index"),
                        "from": sender_addr or tx.get("pubkey", "")[:12],
                        "to": tx.get("to"),
                        "value": tx.get("value"),
                    }
                )
        return jsonify({"transactions": txs})

    return app


def create_user_app() -> Flask:
    app = Flask(__name__)

    @app.get("/")
    def index():
        return render_template("user.html")

    @app.get("/api/settings")
    def api_settings():
        return jsonify(load_settings())

    @app.get("/api/wallets")
    def api_wallets():
        wallets_dir = request.args.get("wallets_dir", DEFAULT_WALLETS_DIR)
        return jsonify({"wallets": list_wallets(wallets_dir)})

    @app.post("/api/tx")
    def api_send_tx():
        payload = request.get_json(force=True)
        wallets_dir = payload.get("wallets_dir", DEFAULT_WALLETS_DIR)
        wallet_name = payload.get("wallet", "")
        to_addr = normalize_hex(payload.get("to", ""))
        amount = int(payload.get("amount", 0))
        node_url = get_node_url(payload)
        if not wallet_name:
            return jsonify({"ok": False, "msg": "missing wallet"}), 400
        if not is_address(to_addr):
            return jsonify({"ok": False, "msg": "invalid recipient address"}), 400
        if amount <= 0:
            return jsonify({"ok": False, "msg": "amount must be > 0"}), 400

        wallet_path = resolve_wallet_path(wallet_name, wallets_dir)
        wallet = read_json(wallet_path)
        if not wallet:
            return jsonify({"ok": False, "msg": f"wallet not found: {wallet_name}"}), 400

        sender_addr = normalize_hex(wallet.get("address", ""))
        pubkey = normalize_hex(wallet.get("public_key_hex", ""))
        if not is_address(sender_addr) or not pubkey:
            return jsonify({"ok": False, "msg": "wallet missing address/pubkey"}), 400

        try:
            r = requests.get(f"{node_url}/nonce/{sender_addr}", timeout=5)
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
            resp = requests.post(node_url + "/tx/new", json=tx.to_dict(), timeout=5)
            return jsonify({"ok": resp.status_code == 200, "status": resp.status_code, "body": resp.text})
        except Exception as exc:
            return jsonify({"ok": False, "msg": f"tx submit failed: {exc}"}), 400

    @app.get("/api/mempool")
    def api_mempool():
        node_url = get_node_url(request.args)
        try:
            r = requests.get(node_url + "/chain", timeout=5)
            r.raise_for_status()
            data = r.json()
        except Exception as exc:
            return jsonify({"mempool_size": 0, "error": str(exc)}), 200
        mempool = data.get("mempool", [])
        return jsonify({"mempool_size": len(mempool)})

    @app.post("/api/mine")
    def api_mine():
        node_url = get_node_url(request.get_json(force=True))
        try:
            resp = requests.post(node_url + "/mine", json={}, timeout=30)
            return jsonify({"ok": resp.status_code == 200, "status": resp.status_code, "body": resp.text})
        except Exception as exc:
            return jsonify({"ok": False, "msg": f"mining failed: {exc}"}), 400

    @app.get("/api/balance")
    def api_balance():
        addr = normalize_hex(request.args.get("address", ""))
        node_url = get_node_url(request.args)
        if not is_address(addr):
            return jsonify({"ok": False, "msg": "invalid address"}), 400
        try:
            r = requests.get(f"{node_url}/balance/{addr}", timeout=5)
            r.raise_for_status()
            return jsonify(r.json())
        except Exception as exc:
            return jsonify({"ok": False, "msg": f"balance fetch failed: {exc}"}), 400

    return app


def main() -> None:
    parser = argparse.ArgumentParser(description="Web UI for the minichain demo")
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=8000)
    parser.add_argument("--mode", choices=["manager", "user"], default="manager")
    args = parser.parse_args()

    if args.mode == "manager":
        app = create_manager_app()
    else:
        app = create_user_app()
    Log.ok(f"Web app ({args.mode}) listening on http://{args.host}:{args.port}")
    app.run(host=args.host, port=args.port, debug=False, use_reloader=False)


if __name__ == "__main__":
    main()
