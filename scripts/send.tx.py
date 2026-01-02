import argparse
import requests
import json

from minichain.storage import read_json
from minichain.models import Transaction, Signature
from minichain.utils import utc_ms, canonical_json, Log
from minichain.crypto import sign_digest, hash_msg


def main():
    p = argparse.ArgumentParser(description="Create + sign a tx from wallet and send to node")
    p.add_argument("--node", required=True, help="Node base url, e.g. http://127.0.0.1:5001")
    p.add_argument("--wallet", default="wallet.json")
    p.add_argument("--to", required=True, help="receiver pubkey hex (compressed)")
    p.add_argument("--amount", type=int, required=True)
    p.add_argument("--nonce", type=int, default=None, help="manual nonce; if omitted node-side convenience endpoint can be used")
    args = p.parse_args()

    w = read_json(args.wallet)
    if not w:
        raise SystemExit(f"wallet not found: {args.wallet}")

    sender_pub = w["public_key_hex"]
    sender_priv = w["private_key_hex"]

    if args.nonce is None:
        # Use convenience endpoint to let node compute nonce
        r = requests.post(args.node.rstrip("/") + "/local/make_tx", json={
            "receiver_pubkey": args.to,
            "amount": args.amount
        }, timeout=5)
        print(r.status_code, r.text)
        return

    tx = Transaction(
        sender_pubkey=sender_pub,
        receiver_pubkey=args.to,
        amount=args.amount,
        nonce=args.nonce,
        timestamp_ms=utc_ms(),
        signature=None
    )
    digest = hash_msg(canonical_json(tx.payload_dict()))
    r_hex, s_hex = sign_digest(sender_priv, digest)
    tx.signature = Signature(r=r_hex, s=s_hex)

    r = requests.post(args.node.rstrip("/") + "/tx/new", json=tx.to_dict(), timeout=5)
    print(r.status_code, r.text)
    if r.status_code == 200:
        Log.ok("Transaction submitted")
    else:
        Log.warn("Transaction rejected")


if __name__ == "__main__":
    main()
