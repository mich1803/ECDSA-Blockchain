import json
import time
import hashlib
from typing import Any, Dict


def utc_ms() -> int:
    return int(time.time() * 1000)


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


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
