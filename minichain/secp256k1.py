# minichain/secp256k1.py
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional, Tuple

import hashlib
import hmac
import secrets


# ---------------- secp256k1 parameters ----------------
# Curve: y^2 = x^3 + 7 over Fp
P  = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
N  = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
A  = 0
B  = 7

Gx = 55066263022277343669578718895168534326250603453777594175500187360389116729240
Gy = 32670510020758816978083085130507043184471273380659243275938904335757337482424


@dataclass(frozen=True)
class Point:
    x: int
    y: int


INF: Optional[Point] = None  # point at infinity


# ---------------- basic math helpers ----------------
def mod_inv(a: int, m: int) -> int:
    """Modular inverse (Extended Euclid)."""
    a %= m
    if a == 0:
        raise ZeroDivisionError("inverse of 0")
    lm, hm = 1, 0
    low, high = a, m
    while low > 1:
        r = high // low
        nm = hm - lm * r
        new = high - low * r
        hm, lm = lm, nm
        high, low = low, new
    return lm % m


def is_on_curve(pt: Optional[Point]) -> bool:
    if pt is None:
        return True
    x = pt.x % P
    y = pt.y % P
    return (y * y - (x * x * x + A * x + B)) % P == 0


def point_neg(pt: Optional[Point]) -> Optional[Point]:
    if pt is None:
        return None
    return Point(pt.x % P, (-pt.y) % P)


def point_add(p1: Optional[Point], p2: Optional[Point]) -> Optional[Point]:
    """Elliptic curve point addition over secp256k1."""
    if p1 is None:
        return p2
    if p2 is None:
        return p1

    x1, y1 = p1.x % P, p1.y % P
    x2, y2 = p2.x % P, p2.y % P

    # P + (-P) = INF
    if x1 == x2 and (y1 + y2) % P == 0:
        return None

    if x1 == x2 and y1 == y2:
        # doubling
        if y1 == 0:
            return None
        lam = (3 * x1 * x1 + A) * mod_inv(2 * y1, P) % P
    else:
        # addition
        lam = (y2 - y1) * mod_inv(x2 - x1, P) % P

    x3 = (lam * lam - x1 - x2) % P
    y3 = (lam * (x1 - x3) - y1) % P
    return Point(x3, y3)


def scalar_mul(k: int, pt: Optional[Point]) -> Optional[Point]:
    """Double-and-add scalar multiplication."""
    if pt is None:
        return None
    k %= N
    if k == 0:
        return None
    if k < 0:
        return scalar_mul(-k, point_neg(pt))

    result: Optional[Point] = None
    addend: Optional[Point] = pt

    while k:
        if k & 1:
            result = point_add(result, addend)
        addend = point_add(addend, addend)
        k >>= 1

    return result


def sqrt_mod_p(a: int) -> int:
    """
    Since P % 4 == 3 for secp256k1, sqrt(a) = a^((P+1)/4) mod P.
    Returns one of the two roots.
    """
    return pow(a % P, (P + 1) // 4, P)


# ---------------- pubkey encoding/decoding ----------------
def point_to_uncompressed_bytes(pt: Point) -> bytes:
    if not is_on_curve(pt):
        raise ValueError("Point not on curve")
    return b"\x04" + (pt.x % P).to_bytes(32, "big") + (pt.y % P).to_bytes(32, "big")


def point_to_compressed_bytes(pt: Point) -> bytes:
    if not is_on_curve(pt):
        raise ValueError("Point not on curve")
    prefix = 0x02 if (pt.y % P) % 2 == 0 else 0x03
    return bytes([prefix]) + (pt.x % P).to_bytes(32, "big")


def decompress_pubkey(pub_hex: str) -> Point:
    """
    Accepts:
      - compressed: 33 bytes hex (02/03 + x32)
      - uncompressed: 65 bytes hex (04 + x32 + y32)
    Returns a Point on the curve.
    """
    b = bytes.fromhex(pub_hex)
    if len(b) == 33 and b[0] in (2, 3):
        prefix = b[0]
        x = int.from_bytes(b[1:], "big")
        y2 = (pow(x, 3, P) + B) % P
        y = sqrt_mod_p(y2)
        # choose root to match prefix parity
        if (y & 1) != (prefix & 1):
            y = (-y) % P
        pt = Point(x, y)
        if not is_on_curve(pt):
            raise ValueError("Invalid compressed pubkey")
        return pt

    if len(b) == 65 and b[0] == 4:
        x = int.from_bytes(b[1:33], "big")
        y = int.from_bytes(b[33:], "big")
        pt = Point(x, y)
        if not is_on_curve(pt):
            raise ValueError("Invalid uncompressed pubkey")
        return pt

    raise ValueError("Invalid pubkey encoding")


# ---------------- RFC6979 deterministic nonce (HMAC-SHA256) ----------------
def _bits2int(b: bytes) -> int:
    i = int.from_bytes(b, "big")
    blen = len(b) * 8
    nlen = N.bit_length()
    if blen > nlen:
        i >>= (blen - nlen)
    return i


def _int2octets(x: int) -> bytes:
    return (x % N).to_bytes(32, "big")


def _bits2octets(b: bytes) -> bytes:
    z1 = _bits2int(b)
    z2 = z1 % N
    return _int2octets(z2)


def rfc6979_nonce(priv_int: int, digest32: bytes) -> int:
    """RFC6979 nonce generation for ECDSA using HMAC-SHA256."""
    if len(digest32) != 32:
        raise ValueError("digest32 must be 32 bytes")
    if not (1 <= priv_int < N):
        raise ValueError("priv_int out of range")

    x = _int2octets(priv_int)
    h1 = digest32

    V = b"\x01" * 32
    K = b"\x00" * 32

    K = hmac.new(K, V + b"\x00" + x + _bits2octets(h1), hashlib.sha256).digest()
    V = hmac.new(K, V, hashlib.sha256).digest()
    K = hmac.new(K, V + b"\x01" + x + _bits2octets(h1), hashlib.sha256).digest()
    V = hmac.new(K, V, hashlib.sha256).digest()

    while True:
        V = hmac.new(K, V, hashlib.sha256).digest()
        k = _bits2int(V)
        if 1 <= k < N:
            return k
        K = hmac.new(K, V + b"\x00", hashlib.sha256).digest()
        V = hmac.new(K, V, hashlib.sha256).digest()


# ---------------- ECDSA sign/verify (classic) ----------------
def ecdsa_sign_digest(
    priv_hex: str,
    digest32: bytes,
    *,
    k: Optional[int] = None,
    enforce_low_s: bool = True
) -> Tuple[str, str]:
    """
    ECDSA sign over secp256k1.
    Returns (r_hex, s_hex), both 32-byte hex strings.
    If k is None => deterministic RFC6979.
    """
    if len(digest32) != 32:
        raise ValueError("digest32 must be 32 bytes")

    x = int(priv_hex, 16)
    if not (1 <= x < N):
        raise ValueError("Invalid private key")

    z = int.from_bytes(digest32, "big")
    G = Point(Gx, Gy)

    while True:
        kk = (k if k is not None else rfc6979_nonce(x, digest32)) % N
        if kk == 0:
            if k is not None:
                raise ValueError("k == 0 mod N")
            continue

        R = scalar_mul(kk, G)
        if R is None:
            if k is not None:
                raise ValueError("R == INF")
            continue

        r = R.x % N
        if r == 0:
            if k is not None:
                raise ValueError("r == 0")
            continue

        s = (mod_inv(kk, N) * (z + r * x)) % N
        if s == 0:
            if k is not None:
                raise ValueError("s == 0")
            continue

        # “low-s” rule to reduce malleability (common practice in Bitcoin/Ethereum tooling)
        if enforce_low_s and s > (N // 2):
            s = N - s

        return r.to_bytes(32, "big").hex(), s.to_bytes(32, "big").hex()


def ecdsa_verify_digest(pub_hex: str, digest32: bytes, r_hex: str, s_hex: str) -> bool:
    """
    Standard ECDSA verification:
      w = s^{-1} mod n
      u1 = z*w mod n
      u2 = r*w mod n
      R  = u1*G + u2*Q
      valid iff r == R.x mod n
    """
    if len(digest32) != 32:
        return False

    try:
        Q = decompress_pubkey(pub_hex)
    except Exception:
        return False

    if not is_on_curve(Q):
        return False

    try:
        r = int(r_hex, 16)
        s = int(s_hex, 16)
    except Exception:
        return False

    if not (1 <= r < N and 1 <= s < N):
        return False

    z = int.from_bytes(digest32, "big")

    try:
        w = mod_inv(s, N)
    except Exception:
        return False

    u1 = (z * w) % N
    u2 = (r * w) % N

    G = Point(Gx, Gy)
    P1 = scalar_mul(u1, G)
    P2 = scalar_mul(u2, Q)
    R = point_add(P1, P2)

    if R is None:
        return False

    return (R.x % N) == r


# ---------------- keypair generation ----------------
@dataclass(frozen=True)
class Keypair:
    private_key_hex: str       # 32-byte hex
    public_key_hex: str        # compressed hex (33 bytes)


def generate_keypair() -> Keypair:
    """
    Generate a secp256k1 keypair (priv, pub_compressed).
    """
    priv = secrets.randbelow(N - 1) + 1
    G = Point(Gx, Gy)
    Q = scalar_mul(priv, G)
    if Q is None:
        # practically impossible; but keep it robust
        raise RuntimeError("Generated INF pubkey")
    return Keypair(
        private_key_hex=priv.to_bytes(32, "big").hex(),
        public_key_hex=point_to_compressed_bytes(Q).hex()
    )
