from __future__ import annotations
from dataclasses import dataclass
from typing import List, Dict, Any, Optional, Tuple
import time

from .models import Transaction, Block, Signature
from .utils import canonical_json, sha256_hex, utc_ms, Log
from .crypto import hash_msg, verify_digest


@dataclass
class ChainConfig:
    difficulty: int = 4
    max_txs_per_block: int = 50


class Blockchain:
    def __init__(self, cfg: ChainConfig):
        self.cfg = cfg
        self.chain: List[Block] = []
        self.mempool: List[Transaction] = []
        # Anti-replay / ordering per sender
        self.last_nonce_by_sender: Dict[str, int] = {}
        # Optional account balances (simple demo)
        self.balances: Dict[str, int] = {}  # pubkey -> int

    # ---------------- Genesis ----------------
    def create_genesis(self) -> None:
        if self.chain:
            return
        genesis = Block(
            index=0,
            timestamp_ms=utc_ms(),
            transactions=[],
            previous_hash="0" * 64,
            difficulty=self.cfg.difficulty,
            nonce=0,
            block_hash=""
        )
        genesis.block_hash = self.compute_block_hash(genesis)
        self.chain.append(genesis)
        Log.ok("Genesis block created")

    # ---------------- Hashing ----------------
    def compute_block_hash(self, block: Block) -> str:
        header = block.header_dict()
        return sha256_hex(canonical_json(header))

    def valid_pow(self, block_hash: str, difficulty: int) -> bool:
        return block_hash.startswith("0" * difficulty)

    # ---------------- TX validation ----------------
    def tx_digest(self, tx: Transaction) -> bytes:
        payload = canonical_json(tx.payload_dict())
        return hash_msg(payload)

    def verify_tx_signature(self, tx: Transaction) -> bool:
        if tx.signature is None:
            return False
        digest = self.tx_digest(tx)
        return verify_digest(
            tx.sender_pubkey,
            digest,
            tx.signature.r,
            tx.signature.s
        )

    def check_tx_rules(self, tx: Transaction) -> Tuple[bool, str]:
        if tx.amount <= 0:
            return False, "amount must be > 0"
        if not tx.sender_pubkey or not tx.receiver_pubkey:
            return False, "missing pubkey"
        if tx.signature is None:
            return False, "missing signature"
        if not self.verify_tx_signature(tx):
            return False, "invalid ECDSA signature"

        last = self.last_nonce_by_sender.get(tx.sender_pubkey, -1)
        if tx.nonce <= last:
            return False, f"replay or out-of-order nonce (got {tx.nonce}, last {last})"

        # Optional balance check (simple account model)
        sender_bal = self.balances.get(tx.sender_pubkey, 0)
        if sender_bal < tx.amount:
            return False, f"insufficient funds (bal={sender_bal}, need={tx.amount})"

        return True, "ok"

    def apply_tx(self, tx: Transaction) -> None:
        # Update nonce and balances
        self.last_nonce_by_sender[tx.sender_pubkey] = tx.nonce
        self.balances[tx.sender_pubkey] = self.balances.get(tx.sender_pubkey, 0) - tx.amount
        self.balances[tx.receiver_pubkey] = self.balances.get(tx.receiver_pubkey, 0) + tx.amount

    # ---------------- Mempool ----------------
    def add_tx_to_mempool(self, tx: Transaction) -> Tuple[bool, str]:
        ok, why = self.check_tx_rules(tx)
        if not ok:
            return False, why

        # Avoid duplicates by (sender, nonce)
        for t in self.mempool:
            if t.sender_pubkey == tx.sender_pubkey and t.nonce == tx.nonce:
                return False, "duplicate tx"
        self.mempool.append(tx)
        return True, "accepted"

    # ---------------- Blocks ----------------
    def make_candidate_block(self) -> Block:
        prev = self.chain[-1]
        txs = self.mempool[: self.cfg.max_txs_per_block]
        blk = Block(
            index=prev.index + 1,
            timestamp_ms=utc_ms(),
            transactions=txs,
            previous_hash=prev.block_hash,
            difficulty=self.cfg.difficulty,
            nonce=0,
            block_hash=""
        )
        return blk

    def mine_block(self, blk: Block, max_tries: int = 5_000_000) -> Tuple[bool, Block, int]:
        """
        Light PoW: find nonce so hash starts with 'difficulty' zeros.
        Returns (success, block, tries)
        """
        tries = 0
        start = time.time()
        while tries < max_tries:
            blk.nonce = tries
            h = self.compute_block_hash(blk)
            if self.valid_pow(h, blk.difficulty):
                blk.block_hash = h
                return True, blk, tries
            tries += 1
        blk.block_hash = self.compute_block_hash(blk)
        return False, blk, tries

    def validate_block(self, blk: Block) -> Tuple[bool, str]:
        if not self.chain:
            return False, "no genesis"

        last = self.chain[-1]
        if blk.index != last.index + 1:
            return False, f"bad index (got {blk.index}, expected {last.index + 1})"
        if blk.previous_hash != last.block_hash:
            return False, "bad previous_hash"
        if self.compute_block_hash(blk) != blk.block_hash:
            return False, "bad block hash"
        if not self.valid_pow(blk.block_hash, blk.difficulty):
            return False, "invalid PoW (difficulty not satisfied)"

        # Validate txs (signature + nonce + balances) in-order
        # We must simulate application without mutating state if invalid.
        snapshot_nonce = dict(self.last_nonce_by_sender)
        snapshot_bal = dict(self.balances)

        for tx in blk.transactions:
            ok, why = self.check_tx_rules(tx)
            if not ok:
                self.last_nonce_by_sender = snapshot_nonce
                self.balances = snapshot_bal
                return False, f"invalid tx in block: {why}"
            self.apply_tx(tx)

        return True, "ok"

    def add_block(self, blk: Block) -> Tuple[bool, str]:
        ok, why = self.validate_block(blk)
        if not ok:
            return False, why

        # Remove included txs from mempool
        included = {(t.sender_pubkey, t.nonce) for t in blk.transactions}
        self.mempool = [t for t in self.mempool if (t.sender_pubkey, t.nonce) not in included]

        self.chain.append(blk)
        return True, "block appended"

    # ---------------- Sync helpers ----------------
    def chain_as_dict(self) -> Dict[str, Any]:
        return {
            "chain": [b.to_dict() for b in self.chain],
            "mempool": [t.to_dict() for t in self.mempool],
            "balances": self.balances,
            "last_nonce_by_sender": self.last_nonce_by_sender
        }

    def replace_chain_if_better(self, new_chain: List[Block]) -> Tuple[bool, str]:
        """
        Naive "longest chain wins".
        For a LAN demo this is enough.
        """
        if len(new_chain) <= len(self.chain):
            return False, "not longer"

        # Validate from genesis
        tmp = Blockchain(self.cfg)
        tmp.create_genesis()

        # For fairness: seed initial balances from our current genesis state
        tmp.balances = dict(self.balances)
        tmp.last_nonce_by_sender = dict(self.last_nonce_by_sender)
        # But this would already include effects; simplest: reset balances & nonces.
        # For a clean demo, we keep balances from a known "faucet" initialization (see node startup).
        # We'll do the strict approach: reset, and require a shared initial faucet state.
        tmp.balances = {}
        tmp.last_nonce_by_sender = {}

        # skip genesis index 0, assume it's compatible
        for blk in new_chain[1:]:
            ok, why = tmp.add_block(blk)
            if not ok:
                return False, f"new chain invalid: {why}"

        self.chain = tmp.chain
        self.mempool = tmp.mempool
        self.balances = tmp.balances
        self.last_nonce_by_sender = tmp.last_nonce_by_sender
        return True, "chain replaced"
