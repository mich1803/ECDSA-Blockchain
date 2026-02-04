import json
import time
import hashlib
from typing import Any


def utc_ms() -> int:
    return int(time.time() * 1000)


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_bytes(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def keccak256(data: bytes) -> bytes:
    """
    Keccak-256 (Ethereum). MUST be consistent across all nodes.
    We intentionally DO NOT fallback to SHA-256 because that would
    change address derivation and signature verification across machines.
    """
    try:
        from Crypto.Hash import keccak  # type: ignore
        k = keccak.new(digest_bits=256)
        k.update(data)
        return k.digest()
    except Exception as e:
        raise RuntimeError(
            "Keccak256 unavailable. Install pycryptodome on ALL nodes: "
            "pip install pycryptodome. Original error: " + str(e)
        )


def canonical_json(obj: Any) -> bytes:
    """
    Deterministic JSON serialization:
    - sort keys
    - compact separators
    - UTF-8
    """
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def short(s: str, n: int = 10) -> str:
    if len(s) <= n:
        return s
    return s[:n] + "…"


def is_hex(s: str) -> bool:
    try:
        int(s, 16)
        return True
    except Exception:
        return False


def normalize_hex(s: str) -> str:
    """
    Remove optional 0x prefix and lowercase.
    """
    if s.startswith("0x") or s.startswith("0X"):
        s = s[2:]
    return s.lower()


def is_address(addr: str) -> bool:
    """
    Address = 20 bytes = 40 hex chars (no 0x).
    """
    a = normalize_hex(addr)
    return len(a) == 40 and is_hex(a)


class Log:
    @staticmethod
    def info(msg: str) -> None:
        print(f"[INFO] {msg}")

    @staticmethod
    def ok(msg: str) -> None:
        print(f"[ OK ] {msg}")

    @staticmethod
    def warn(msg: str) -> None:
        print(f"[WARN] {msg}")

    @staticmethod
    def err(msg: str) -> None:
        print(f"[ERR ] {msg}")
