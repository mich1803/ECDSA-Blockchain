from __future__ import annotations

from dataclasses import dataclass
from typing import Tuple
import hashlib

from .utils import keccak256
from .secp256k1 import (
    Keypair as SecpKeypair,
    generate_keypair as secp_generate_keypair,
    ecdsa_sign_digest,
    ecdsa_verify_digest,
    decompress_pubkey,
    point_to_uncompressed_bytes,
    point_to_compressed_bytes,
    Point,
)


def hash_msg(message_bytes: bytes) -> bytes:
    """
    We sign a 32-byte digest. For the toy chain we keep SHA-256 for tx/block digesting.
    """
    return hashlib.sha256(message_bytes).digest()


# --- keep same external shape as before ---
@dataclass(frozen=True)
class Keypair:
    private_key_hex: str
    public_key_hex: str  # compressed secp256k1 pubkey hex


def generate_keypair() -> Keypair:
    kp: SecpKeypair = secp_generate_keypair()
    return Keypair(private_key_hex=kp.private_key_hex, public_key_hex=kp.public_key_hex)


# --- minimal replacement for coincurve.PublicKey used by chain/node ---
@dataclass(frozen=True)
class PublicKeyCompat:
    point: Point

    def format(self, compressed: bool = True) -> bytes:
        return point_to_compressed_bytes(self.point) if compressed else point_to_uncompressed_bytes(self.point)


def pubkey_from_hex(pub_hex: str) -> PublicKeyCompat:
    """
    Parse compressed/uncompressed pubkey hex into a compatible object with .format().
    """
    pt = decompress_pubkey(pub_hex)
    return PublicKeyCompat(pt)


def pubkey_to_address(pub_uncompressed_bytes: bytes) -> str:
    """
    Ethereum-style address = last 20 bytes of keccak256(uncompressed_pubkey[1:])
    where uncompressed pubkey is 65 bytes: 0x04 || X(32) || Y(32)
    """
    if len(pub_uncompressed_bytes) != 65 or pub_uncompressed_bytes[0] != 0x04:
        raise ValueError("Expected uncompressed pubkey bytes (65 bytes starting with 0x04)")
    h = keccak256(pub_uncompressed_bytes[1:])
    return h[-20:].hex()


def sign_digest(priv_hex: str, digest32: bytes) -> Tuple[str, str]:
    """
    Pure-Python ECDSA sign -> (r_hex, s_hex) (32-byte hex each)
    """
    return ecdsa_sign_digest(priv_hex, digest32)


def verify_digest(pub_hex: str, digest32: bytes, r_hex: str, s_hex: str) -> bool:
    """
    Pure-Python ECDSA verify
    """
    return ecdsa_verify_digest(pub_hex, digest32, r_hex, s_hex)
