#!/usr/bin/env python3
import argparse
import json
import os
import random
import requests

from coincurve import PublicKey

from minichain.storage import read_json
from minichain.models import Transaction, Signature
from minichain.utils import utc_ms, canonical_json, normalize_hex, is_address, Log
from minichain.crypto import hash_msg, pubkey_from_hex, pubkey_to_address, recover_pubkey_uncompressed

# secp256k1 curve order n
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141


def modinv(a: int, n: int = N) -> int:
    return pow(a % n, -1, n)


def int_from_digest(digest32: bytes) -> int:
    return int.from_bytes(digest32, "big") % N


def scalar_to_32(x: int) -> bytes:
    return (x % N).to_bytes(32, "big")


def find_recovery_id(digest32: bytes, r_hex: str, s_hex: str, expected_addr: str) -> int:
    for v in range(4):
        try:
            rec_un = recover_pubkey_uncompressed(digest32, v, r_hex, s_hex)
            rec_addr = pubkey_to_address(rec_un)
            if rec_addr == expected_addr:
                return v
        except Exception:
            continue
    raise RuntimeError("Could not find a valid recovery id v (0..3).")


def ecdsa_sign_with_k(priv_hex: str, digest32: bytes, k: int, expected_addr: str):
    """Create a valid (v,r,s) ECDSA signature using a chosen nonce k."""
    z = int_from_digest(digest32)
    x = int(priv_hex, 16) % N
    k = k % N
    if k == 0:
        raise ValueError("k must be non-zero")

    # R = k*G
    pubR = PublicKey.from_valid_secret(scalar_to_32(k))
    uncompressed = pubR.format(compressed=False)  # 0x04 || X || Y
    Rx = int.from_bytes(uncompressed[1:33], "big")
    r = Rx % N
    if r == 0:
        raise ValueError("r == 0, choose a different k")

    s = (modinv(k) * (z + r * x)) % N
    if s == 0:
        raise ValueError("s == 0, choose a different k")

    r_hex = r.to_bytes(32, "big").hex()
    s_hex = s.to_bytes(32, "big").hex()
    v = find_recovery_id(digest32, r_hex, s_hex, expected_addr)
    return int(v), r_hex, s_hex


def fetch_nonce(node: str, addr: str) -> int:
    r = requests.get(node.rstrip("/") + f"/nonce/{addr}", timeout=5)
    r.raise_for_status()
    return int(r.json()["nonce"])


def send_tx(node: str, tx: Transaction):
    r = requests.post(node.rstrip("/") + "/tx/new", json=tx.to_dict(), timeout=10)
    return r.status_code, r.text


def main():
    p = argparse.ArgumentParser(description="Generate tx(s) with WEAK ECDSA nonce and send to a minichain node.")
    p.add_argument("--node", required=True, help="e.g. http://127.0.0.1:5001")
    p.add_argument("--wallet", required=True, help="victim wallet json (private key inside!)")
    p.add_argument("--to", required=True, help="receiver address 40-hex (no 0x)")
    p.add_argument("--amount", type=int, default=1)
    p.add_argument("--mode", choices=["reuse", "linear"], default="reuse",
                   help="reuse: same k for 2 tx; linear: k=a*z+b for 3 tx")
    p.add_argument("--outdir", default="weak_nonce", help="where to write tx*.json (default: weak_nonce)")
    args = p.parse_args()

    w = read_json(args.wallet)
    if not w:
        raise SystemExit(f"wallet not found: {args.wallet}")

    priv = w["private_key_hex"]
    pub = pubkey_from_hex(w["public_key_hex"])
    sender_addr = pubkey_to_address(pub.format(compressed=False))

    to = normalize_hex(args.to)
    if not is_address(to):
        raise SystemExit("--to must be a 20-byte address hex (40 hex chars)")

    os.makedirs(args.outdir, exist_ok=True)

    count = 2 if args.mode == "reuse" else 3

    if args.mode == "reuse":
        k0 = random.randrange(1, N)
        Log.warn("Using WEAK nonce mode: reuse (same k for 2 signatures)")
    else:
        a = random.randrange(1, N)
        b = random.randrange(1, N)
        Log.warn("Using WEAK nonce mode: linear (k = a*z + b), will create 3 signatures")
        Log.info(f"(debug) a={hex(a)} b={hex(b)}")

    for i in range(count):
        account_nonce = fetch_nonce(args.node, sender_addr)

        tx = Transaction(
            to=to,
            value=int(args.amount),
            nonce=int(account_nonce),
            timestamp_ms=utc_ms(),
            data="",
            signature=None,
        )
        digest = hash_msg(canonical_json(tx.payload_dict()))

        if args.mode == "reuse":
            k = k0
        else:
            z = int_from_digest(digest)
            k = (a * z + b) % N
            if k == 0:
                k = 1

        v, r_hex, s_hex = ecdsa_sign_with_k(priv, digest, k, sender_addr)
        tx.signature = Signature(v=v, r=r_hex, s=s_hex)

        sc, txt = send_tx(args.node, tx)
        Log.info(f"Sent tx{i+1}: HTTP {sc} {txt}")

        path = os.path.join(args.outdir, f"tx{i+1}.json")
        with open(path, "w", encoding="utf-8") as f:
            json.dump(tx.to_dict(), f, ensure_ascii=False, indent=2)
        Log.ok(f"Wrote {path}")

    Log.ok("Done. Now run recover_privkey.py on the tx*.json files to recover the private key.")


if __name__ == "__main__":
    main()
