import argparse
import requests

from minichain.storage import read_json
from minichain.models import Transaction, Signature
from minichain.utils import utc_ms, canonical_json, Log, normalize_hex, is_address
from minichain.crypto import sign_digest, hash_msg
from minichain.paths import resolve_wallet_path, DEFAULT_WALLETS_DIR


def main():
    p = argparse.ArgumentParser(description="Create + sign a tx (no fees) and send to node")
    p.add_argument("--node", required=True, help="Node base url, e.g. http://127.0.0.1:5001")
    p.add_argument("--wallet", default="wallet.json", help="filename or path. If filename only, loaded from wallets/")
    p.add_argument("--wallets-dir", default=DEFAULT_WALLETS_DIR)
    p.add_argument("--to", required=True, help="receiver address hex (20 bytes, 40 hex chars)")
    p.add_argument("--amount", type=int, required=True, help="value to transfer")
    p.add_argument("--nonce", type=int, default=None, help="manual nonce; if omitted we fetch /nonce/<address>")
    args = p.parse_args()

    wallet_path = resolve_wallet_path(args.wallet, args.wallets_dir)
    w = read_json(wallet_path)
    if not w:
        raise SystemExit(f"wallet not found: {wallet_path}")

    sender_priv = normalize_hex(w.get("private_key_hex", ""))
    sender_pub = normalize_hex(w.get("public_key_hex", ""))
    sender_addr = normalize_hex(w.get("address", ""))

    if len(sender_priv) != 64:
        raise SystemExit("wallet missing a valid 'private_key_hex' (32 bytes hex)")
    if not sender_pub:
        raise SystemExit("wallet missing a valid 'public_key_hex'")
    if not is_address(sender_addr):
        raise SystemExit("wallet missing a valid 'address'. Recreate with scripts/create_wallet.py")

    to = normalize_hex(args.to)
    if not is_address(to):
        raise SystemExit("--to must be a 20-byte address hex (40 hex chars)")

    if int(args.amount) <= 0:
        raise SystemExit("--amount must be > 0")

    base = args.node.rstrip("/")

    nonce = args.nonce
    if nonce is None:
        r = requests.get(f"{base}/nonce/{sender_addr}", timeout=5)
        if r.status_code != 200:
            raise SystemExit(f"failed to fetch nonce: {r.status_code} {r.text}")
        nonce = int(r.json()["nonce"])

    tx = Transaction(
        to=to,
        value=int(args.amount),
        nonce=int(nonce),
        timestamp_ms=utc_ms(),
        pubkey=sender_pub,  # pubkey visible
        data="",
        signature=None,
    )

    digest = hash_msg(canonical_json(tx.payload_dict()))
    r_hex, s_hex = sign_digest(sender_priv, digest)
    tx.signature = Signature(r=r_hex, s=s_hex)

    r = requests.post(base + "/tx/new", json=tx.to_dict(), timeout=5)
    print(r.status_code, r.text)
    if r.status_code == 200:
        Log.ok("Transaction submitted")
    else:
        Log.warn("Transaction rejected")


if __name__ == "__main__":
    main()
