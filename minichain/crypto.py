from __future__ import annotations
from dataclasses import dataclass
from typing import Tuple, Optional
import hashlib

from coincurve import PrivateKey, PublicKey  # secp256k1


def hash_msg(message_bytes: bytes) -> bytes:
    # For blockchain-like signing we sign a hash, as typical in practice.
    return hashlib.sha256(message_bytes).digest()


@dataclass(frozen=True)
class Keypair:
    private_key_hex: str
    public_key_hex: str  # compressed secp256k1 pubkey


def generate_keypair() -> Keypair:
    priv = PrivateKey()
    pub = priv.public_key
    return Keypair(
        private_key_hex=priv.to_hex(),
        public_key_hex=pub.format(compressed=True).hex()
    )


def pubkey_from_hex(pub_hex: str) -> PublicKey:
    return PublicKey(bytes.fromhex(pub_hex))


def privkey_from_hex(priv_hex: str) -> PrivateKey:
    return PrivateKey(bytes.fromhex(priv_hex))


def sign_digest(priv_hex: str, digest32: bytes) -> Tuple[str, str]:
    """
    Returns (r_hex, s_hex) from a DER signature.
    coincurve uses RFC6979 deterministic nonce by default for sign().
    """
    priv = privkey_from_hex(priv_hex)
    sig_der = priv.sign(digest32, hasher=None)  # digest already hashed
    # Parse DER -> (r,s) using coincurve's helper by re-decoding via PublicKey.verify?
    # We'll implement a minimal DER parser for ECDSA INTEGERs.
    r, s = der_to_rs(sig_der)
    return (r.to_bytes(32, "big").hex(), s.to_bytes(32, "big").hex())


def verify_digest(pub_hex: str, digest32: bytes, r_hex: str, s_hex: str) -> bool:
    pub = pubkey_from_hex(pub_hex)
    sig_der = rs_to_der(int(r_hex, 16), int(s_hex, 16))
    try:
        return pub.verify(sig_der, digest32, hasher=None)
    except Exception:
        return False


# --- Minimal DER helpers (ECDSA signature) ---
# DER format: 0x30 len 0x02 lenR R 0x02 lenS S

def der_to_rs(sig_der: bytes) -> Tuple[int, int]:
    if len(sig_der) < 8 or sig_der[0] != 0x30:
        raise ValueError("Invalid DER signature")
    total_len = sig_der[1]
    if total_len + 2 != len(sig_der):
        # Some DER encodings use long-form length; not expected here.
        # coincurve typically emits short-form for fixed-size ECDSA.
        pass

    if sig_der[2] != 0x02:
        raise ValueError("Invalid DER (no integer for r)")
    len_r = sig_der[3]
    r_bytes = sig_der[4:4 + len_r]

    idx = 4 + len_r
    if sig_der[idx] != 0x02:
        raise ValueError("Invalid DER (no integer for s)")
    len_s = sig_der[idx + 1]
    s_bytes = sig_der[idx + 2: idx + 2 + len_s]

    r = int.from_bytes(r_bytes, "big")
    s = int.from_bytes(s_bytes, "big")
    return r, s


def rs_to_der(r: int, s: int) -> bytes:
    r_b = int_to_der_integer_bytes(r)
    s_b = int_to_der_integer_bytes(s)
    seq = b"\x02" + bytes([len(r_b)]) + r_b + b"\x02" + bytes([len(s_b)]) + s_b
    return b"\x30" + bytes([len(seq)]) + seq


def int_to_der_integer_bytes(x: int) -> bytes:
    b = x.to_bytes((x.bit_length() + 7) // 8 or 1, "big")
    # If highest bit is set, prepend 0x00 to make it positive.
    if b[0] & 0x80:
        b = b"\x00" + b
    return b
