from __future__ import annotations
from dataclasses import dataclass
from typing import Dict, Any, Optional, List

from .utils import normalize_hex


@dataclass
class Signature:
    """
    Ethereum-like: (v, r, s) where v is recovery id (0..3 in this toy).
    r, s are 32-byte hex strings.
    """
    v: int
    r: str
    s: str

    def to_dict(self) -> Dict[str, Any]:
        return {"v": int(self.v), "r": self.r, "s": self.s}


@dataclass
class Transaction:
    """
    Ethereum-like transaction (simplified, no fees/gas):
    - sender is NOT included (recovered from signature)
    """
    to: str               # 20-byte address hex (40 chars, no 0x)
    value: int
    nonce: int
    timestamp_ms: int
    data: str = ""        # optional hex payload (no 0x)
    signature: Optional[Signature] = None

    def payload_dict(self) -> Dict[str, Any]:
        """
        Deterministic payload that gets signed (exclude signature).
        """
        return {
            "to": normalize_hex(self.to),
            "value": int(self.value),
            "nonce": int(self.nonce),
            "timestamp_ms": int(self.timestamp_ms),
            "data": normalize_hex(self.data) if self.data else "",
        }

    def to_dict(self) -> Dict[str, Any]:
        d = self.payload_dict()
        d["signature"] = self.signature.to_dict() if self.signature else None
        return d

    @staticmethod
    def from_dict(d: Dict[str, Any]) -> "Transaction":
        sig = d.get("signature")
        signature = None
        if isinstance(sig, dict) and "v" in sig and "r" in sig and "s" in sig:
            signature = Signature(v=int(sig["v"]), r=sig["r"], s=sig["s"])

        return Transaction(
            to=d["to"],
            value=int(d["value"]),
            nonce=int(d["nonce"]),
            timestamp_ms=int(d["timestamp_ms"]),
            data=d.get("data", "") or "",
            signature=signature,
        )


@dataclass
class Block:
    index: int
    timestamp_ms: int
    transactions: List[Transaction]
    previous_hash: str
    difficulty: int
    nonce: int
    proposer: str          # address (20 bytes hex)
    block_hash: str

    def header_dict(self) -> Dict[str, Any]:
        return {
            "index": int(self.index),
            "timestamp_ms": int(self.timestamp_ms),
            "transactions": [tx.to_dict() for tx in self.transactions],
            "previous_hash": self.previous_hash,
            "difficulty": int(self.difficulty),
            "nonce": int(self.nonce),
            "proposer": normalize_hex(self.proposer),
        }

    def to_dict(self) -> Dict[str, Any]:
        d = self.header_dict()
        d["hash"] = self.block_hash
        return d

    @staticmethod
    def from_dict(d: Dict[str, Any]) -> "Block":
        txs = [Transaction.from_dict(x) for x in d["transactions"]]
        return Block(
            index=int(d["index"]),
            timestamp_ms=int(d["timestamp_ms"]),
            transactions=txs,
            previous_hash=d["previous_hash"],
            difficulty=int(d["difficulty"]),
            nonce=int(d["nonce"]),
            proposer=d.get("proposer", ""),
            block_hash=d["hash"],
        )
