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


def gauss_solve_mod(M, b, n=N):
    """Solve M*x=b over Z_n with Gaussian elimination (square matrix)."""
    m = len(M)
    A = [list(map(lambda x: x % n, M[i])) + [b[i] % n] for i in range(m)]

    col = 0
    for row in range(m):
        pivot = None
        for r in range(row, m):
            if A[r][col] % n != 0:
                pivot = r
                break
        if pivot is None:
            raise ValueError("Singular matrix (no pivot). Regenerate txs (different randomness).")
        A[row], A[pivot] = A[pivot], A[row]

        inv_p = modinv(A[row][col], n)
        for c in range(col, m + 1):
            A[row][c] = (A[row][c] * inv_p) % n

        for r in range(m):
            if r == row:
                continue
            factor = A[r][col] % n
            if factor == 0:
                continue
            for c in range(col, m + 1):
                A[r][c] = (A[r][c] - factor * A[row][c]) % n

        col += 1
        if col >= m:
            break

    return [A[i][m] % n for i in range(m)]


def recover_from_linear(txs: List[Transaction]) -> Tuple[int, int, int]:
    """Recover (a,b,x) when k_i = a*z_i + b (mod n). Needs 3 signatures."""
    if len(txs) != 3:
        raise ValueError("linear mode needs exactly 3 tx files")

    rows = []
    rhs = []
    for tx in txs:
        z, r, s = tx_z_r_s(tx)
        rows.append([(s * z) % N, s % N, (-r) % N])
        rhs.append(z % N)

    a, b, x = gauss_solve_mod(rows, rhs, N)
    return a, b, x


def main():
    p = argparse.ArgumentParser(description="Recover a secp256k1 private key from weak ECDSA nonce patterns.")
    p.add_argument("--mode", choices=["reuse", "linear"], required=True)
    p.add_argument("--tx", nargs="+", required=True, help="paths to tx JSON files (2 for reuse, 3 for linear)")
    p.add_argument("--pubkey", default=None, help="optional: victim public key hex to verify recovered key")
    args = p.parse_args()

    txs = [load_tx(x) for x in args.tx]

    if args.mode == "reuse":
        x = recover_from_reuse(txs)
        Log.ok(f"Recovered private key x = {hex(x)}")
    else:
        a, b, x = recover_from_linear(txs)
        Log.ok(f"Recovered a = {hex(a)}")
        Log.ok(f"Recovered b = {hex(b)}")
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
            Log.warn("Tip: in linear mode, regenerate txs if the matrix was (unluckily) singular.")


if __name__ == "__main__":
    main()
