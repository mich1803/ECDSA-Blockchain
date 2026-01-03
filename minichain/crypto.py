from __future__ import annotations
from dataclasses import dataclass
from typing import Tuple
import hashlib

from coincurve import PrivateKey, PublicKey  # secp256k1

from .utils import keccak256


def hash_msg(message_bytes: bytes) -> bytes:
    """
    We sign a 32-byte digest. For the toy chain we keep SHA-256 for tx/block digesting.
    (Ethereum uses keccak for RLP-encoded payloads; here canonical_json + sha256 is ok.)
    """
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


def pubkey_to_address(pub_uncompressed_bytes: bytes) -> str:
    """
    Ethereum address = last 20 bytes of keccak256(uncompressed_pubkey[1:])
    where uncompressed pubkey is 65 bytes: 0x04 || X(32) || Y(32)
    """
    if len(pub_uncompressed_bytes) != 65 or pub_uncompressed_bytes[0] != 0x04:
        raise ValueError("Expected uncompressed pubkey bytes (65 bytes starting with 0x04)")
    h = keccak256(pub_uncompressed_bytes[1:])  # 64 bytes payload
    return h[-20:].hex()


# ---------------- ECDSA DER helpers (legacy r/s) ----------------
# DER format: 0x30 len 0x02 lenR R 0x02 lenS S

def der_to_rs(sig_der: bytes) -> Tuple[int, int]:
    if len(sig_der) < 8 or sig_der[0] != 0x30:
        raise ValueError("Invalid DER signature")
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


def int_to_der_integer_bytes(x: int) -> bytes:
    b = x.to_bytes((x.bit_length() + 7) // 8 or 1, "big")
    if b[0] & 0x80:
        b = b"\x00" + b
    return b


def rs_to_der(r: int, s: int) -> bytes:
    r_b = int_to_der_integer_bytes(r)
    s_b = int_to_der_integer_bytes(s)
    seq = b"\x02" + bytes([len(r_b)]) + r_b + b"\x02" + bytes([len(s_b)]) + s_b
    return b"\x30" + bytes([len(seq)]) + seq


def sign_digest(priv_hex: str, digest32: bytes) -> Tuple[str, str]:
    """
    Legacy helper: returns (r_hex, s_hex) from a DER signature.
    """
    priv = privkey_from_hex(priv_hex)
    sig_der = priv.sign(digest32, hasher=None)
    r, s = der_to_rs(sig_der)
    return (r.to_bytes(32, "big").hex(), s.to_bytes(32, "big").hex())


def verify_digest(pub_hex: str, digest32: bytes, r_hex: str, s_hex: str) -> bool:
    pub = pubkey_from_hex(pub_hex)
    sig_der = rs_to_der(int(r_hex, 16), int(s_hex, 16))
    try:
        return pub.verify(sig_der, digest32, hasher=None)
    except Exception:
        return False


# ---------------- Ethereum-like recoverable signatures ----------------

def sign_digest_recoverable(priv_hex: str, digest32: bytes) -> Tuple[int, str, str]:
    """
    Returns (v, r_hex, s_hex) where v is recovery id in [0..3].
    coincurve returns 65 bytes: r(32) || s(32) || recid(1)
    """
    priv = privkey_from_hex(priv_hex)
    sig65 = priv.sign_recoverable(digest32, hasher=None)
    r = sig65[0:32]
    s = sig65[32:64]
    v = sig65[64]
    return int(v), r.hex(), s.hex()


def recover_pubkey_uncompressed(digest32: bytes, v: int, r_hex: str, s_hex: str) -> bytes:
    """
    Recover uncompressed pubkey bytes (65 bytes 0x04||X||Y) from signature and digest.
    """
    if v < 0 or v > 3:
        raise ValueError("recovery id v must be 0..3")
    sig65 = bytes.fromhex(r_hex) + bytes.fromhex(s_hex) + bytes([v])
    pub = PublicKey.from_signature_and_message(sig65, digest32, hasher=None)
    return pub.format(compressed=False)


def recover_address(digest32: bytes, v: int, r_hex: str, s_hex: str) -> str:
    pub_un = recover_pubkey_uncompressed(digest32, v, r_hex, s_hex)
    return pubkey_to_address(pub_un)
