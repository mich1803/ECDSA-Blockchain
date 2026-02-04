#!/usr/bin/env python3
import argparse
import json
from typing import List, Tuple

from minichain.models import Transaction
from minichain.utils import canonical_json, Log, normalize_hex
from minichain.crypto import hash_msg, pubkey_from_hex, pubkey_to_address

# secp256k1 order
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141


def modinv(a: int, n: int = N) -> int:
    return pow(a % n, -1, n)


def int_from_digest(digest32: bytes) -> int:
    return int.from_bytes(digest32, "big") % N


def load_tx(path: str) -> Transaction:
    with open(path, "r", encoding="utf-8") as f:
        d = json.load(f)
    return Transaction.from_dict(d)


def tx_z_r_s(tx: Transaction) -> Tuple[int, int, int]:
    if not tx.signature:
        raise ValueError("tx missing signature")
    digest = hash_msg(canonical_json(tx.payload_dict()))
    z = int_from_digest(digest)
    r = int(tx.signature.r, 16) % N
    s = int(tx.signature.s, 16) % N
    return z, r, s


def recover_from_reuse(txs: List[Transaction]) -> int:
    if len(txs) != 2:
        raise ValueError("reuse mode needs exactly 2 tx files")
    z1, r1, s1 = tx_z_r_s(txs[0])
    z2, r2, s2 = tx_z_r_s(txs[1])
    if r1 != r2:
        raise ValueError("These 2 signatures do NOT have the same r (nonce probably not reused).")

    k = ((z1 - z2) * modinv(s1 - s2)) % N
    x = ((s1 * k - z1) * modinv(r1)) % N
    return x


def main():
    p = argparse.ArgumentParser(description="Recover a secp256k1 private key from weak ECDSA nonce reuse.")
    p.add_argument("--mode", choices=["reuse"], required=True)
    p.add_argument("--tx", nargs="+", required=True, help="paths to tx JSON files (2 for reuse)")
    p.add_argument("--pubkey", default=None, help="optional: victim public key hex to verify recovered key")
    args = p.parse_args()

    txs = [load_tx(x) for x in args.tx]

    x = recover_from_reuse(txs)
    Log.ok(f"Recovered private key x = {hex(x)}")

    # Verify if pubkey provided
    if args.pubkey:
        pub = pubkey_from_hex(args.pubkey)
        addr_expected = pubkey_to_address(pub.format(compressed=False))
        Log.info(f"Expected address from pubkey: {addr_expected}")
    else:
        addr_expected = None

    # derive address from recovered x
    from coincurve import PrivateKey
    priv = PrivateKey(x.to_bytes(32, "big"))
    addr2 = pubkey_to_address(priv.public_key.format(compressed=False))
    Log.ok(f"Address derived from recovered x: {addr2}")

    if addr_expected:
        if normalize_hex(addr2) == normalize_hex(addr_expected):
            Log.ok("Verification OK: recovered key matches the provided pubkey/address.")
        else:
            Log.warn("Verification FAILED: recovered key does not match the provided pubkey/address.")


if __name__ == "__main__":
    main()
