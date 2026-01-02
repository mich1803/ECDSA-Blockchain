from __future__ import annotations
from dataclasses import dataclass, asdict
from typing import List, Dict, Any, Optional

from .utils import canonical_json


@dataclass
class Signature:
    r: str  # hex (32 bytes)
    s: str  # hex (32 bytes)

    def to_dict(self) -> Dict[str, Any]:
        return {"r": self.r, "s": self.s}


@dataclass
class Transaction:
    sender_pubkey: str
    receiver_pubkey: str
    amount: int
    nonce: int
    timestamp_ms: int
    signature: Optional[Signature] = None

    def payload_dict(self) -> Dict[str, Any]:
        """
        What gets signed (must be deterministic and exclude signature).
        """
        return {
            "sender_pubkey": self.sender_pubkey,
            "receiver_pubkey": self.receiver_pubkey,
            "amount": self.amount,
            "nonce": self.nonce,
            "timestamp_ms": self.timestamp_ms,
        }

    def to_dict(self) -> Dict[str, Any]:
        d = self.payload_dict()
        d["signature"] = self.signature.to_dict() if self.signature else None
        return d

    @staticmethod
    def from_dict(d: Dict[str, Any]) -> "Transaction":
        sig = d.get("signature")
        signature = None
        if isinstance(sig, dict) and "r" in sig and "s" in sig:
            signature = Signature(r=sig["r"], s=sig["s"])
        return Transaction(
            sender_pubkey=d["sender_pubkey"],
            receiver_pubkey=d["receiver_pubkey"],
            amount=int(d["amount"]),
            nonce=int(d["nonce"]),
            timestamp_ms=int(d["timestamp_ms"]),
            signature=signature
        )


@dataclass
class Block:
    index: int
    timestamp_ms: int
    transactions: List[Transaction]
    previous_hash: str
    difficulty: int
    nonce: int
    block_hash: str

    def header_dict(self) -> Dict[str, Any]:
        return {
            "index": self.index,
            "timestamp_ms": self.timestamp_ms,
            "transactions": [tx.to_dict() for tx in self.transactions],
            "previous_hash": self.previous_hash,
            "difficulty": self.difficulty,
            "nonce": self.nonce,
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
            block_hash=d["hash"]
        )
