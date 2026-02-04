from __future__ import annotations
from dataclasses import dataclass
from typing import List, Dict, Any, Optional, Tuple

import time

from .models import Transaction, Block
from .utils import canonical_json, sha256_hex, utc_ms, Log, normalize_hex, is_address, is_hex
from .crypto import hash_msg, verify_digest, pubkey_from_hex, pubkey_to_address


@dataclass
class ChainConfig:
    difficulty: int = 4
    max_txs_per_block: int = 50
    block_reward: int = 1  # optional toy issuance


class Blockchain:
    def __init__(self, cfg: ChainConfig):
        self.cfg = cfg
        self.chain: List[Block] = []
        self.mempool: List[Transaction] = []

        # Ethereum-like state: accounts[address] = {"balance": int, "nonce": int}
        self.accounts: Dict[str, Dict[str, int]] = {}

        # Shared genesis allocation (the key fix)
        self.genesis_alloc: Dict[str, int] = {}

    # ---------------- Genesis allocation ----------------
    def set_genesis_alloc(self, alloc: Dict[str, int]) -> None:
        """
        Set shared initial balances.
        alloc keys are addresses (40 hex chars). Values are ints.
        """
        cleaned: Dict[str, int] = {}
        for k, v in (alloc or {}).items():
            a = normalize_hex(str(k))
            if not is_address(a):
                raise ValueError(f"Invalid address in genesis alloc: {k}")
            cleaned[a] = int(v)
        self.genesis_alloc = cleaned

    def reset_state_to_genesis(self) -> None:
        """
        Reset accounts state to genesis allocation deterministically:
        - balances from genesis_alloc
        - nonce = 0
        """
        self.accounts = {}
        for addr, bal in self.genesis_alloc.items():
            self.accounts[addr] = {"balance": int(bal), "nonce": 0}

    # ---------------- Accounts ----------------
    def get_account(self, addr: str) -> Dict[str, int]:
        a = normalize_hex(addr)
        if a not in self.accounts:
            self.accounts[a] = {"balance": 0, "nonce": 0}
        return self.accounts[a]

    def balance_of(self, addr: str) -> int:
        return int(self.get_account(addr)["balance"])

    def nonce_of(self, addr: str) -> int:
        return int(self.get_account(addr)["nonce"])

    # ---------------- Genesis block ----------------
    def create_genesis(self) -> None:
        if self.chain:
            return
        genesis = Block(
            index=0,
            timestamp_ms=0, #cambiato da utc_ms()
            transactions=[],
            previous_hash="0" * 64,
            difficulty=self.cfg.difficulty,
            nonce=0,
            proposer="0" * 40,
            block_hash="",
        )
        genesis.block_hash = self.compute_block_hash(genesis)
        self.chain.append(genesis)
        Log.ok("Genesis block created")

    # ---------------- Hashing ----------------
    def compute_block_hash(self, block: Block) -> str:
        return sha256_hex(canonical_json(block.header_dict()))

    def valid_pow(self, block_hash: str, difficulty: int) -> bool:
        return block_hash.startswith("0" * difficulty)

    # ---------------- TX digest + sender verification ----------------
    def tx_digest(self, tx: Transaction) -> bytes:
        payload = canonical_json(tx.payload_dict())
        return hash_msg(payload)

    def verify_sender(self, tx: Transaction) -> Tuple[bool, str, str]:
        if tx.signature is None:
            return False, "", "missing signature"
        pub_hex = normalize_hex(tx.pubkey or "")
        if not pub_hex:
            return False, "", "missing sender pubkey"
        if not is_hex(pub_hex) or len(pub_hex) not in (66, 130):
            return False, "", "invalid sender pubkey"
        try:
            pub = pubkey_from_hex(pub_hex)
        except Exception as e:
            return False, "", f"invalid sender pubkey: {e}"
        try:
            digest = self.tx_digest(tx)
            if not verify_digest(pub_hex, digest, tx.signature.r, tx.signature.s):
                return False, "", "signature verification failed"
            sender = pubkey_to_address(pub.format(compressed=False))
            return True, sender, "ok"
        except Exception as e:
            return False, "", f"signature verification failed: {e}"

    # ---------------- TX validation ----------------
    def check_tx_rules(self, tx: Transaction) -> Tuple[bool, str, Optional[str]]:
        if tx.value <= 0:
            return False, "value must be > 0", None

        to = normalize_hex(tx.to)
        if not is_address(to):
            return False, "invalid 'to' address", None

        ok, sender, why = self.verify_sender(tx)
        if not ok:
            return False, why, None

        acc = self.get_account(sender)

        # Ethereum-like: nonce must match EXACTLY
        if tx.nonce != int(acc["nonce"]):
            return False, f"bad nonce (got {tx.nonce}, expected {acc['nonce']})", None

        bal = int(acc["balance"])
        if bal < tx.value:
            return False, f"insufficient funds (bal={bal}, need={tx.value})", None

        return True, "ok", sender

    def apply_tx(self, tx: Transaction, sender_addr: str) -> None:
        sender = normalize_hex(sender_addr)
        receiver = normalize_hex(tx.to)

        sacc = self.get_account(sender)
        racc = self.get_account(receiver)

        sacc["balance"] = int(sacc["balance"]) - int(tx.value)
        racc["balance"] = int(racc["balance"]) + int(tx.value)
        sacc["nonce"] = int(sacc["nonce"]) + 1

    # ---------------- Mempool ----------------
    def add_tx_to_mempool(self, tx: Transaction) -> Tuple[bool, str]:
        ok, why, sender = self.check_tx_rules(tx)
        if not ok or sender is None:
            return False, why

        # avoid duplicates by (sender, nonce)
        for t in self.mempool:
            ok2, s2, _ = self.verify_sender(t)
            if ok2 and s2 == sender and t.nonce == tx.nonce:
                return False, "duplicate tx"

        self.mempool.append(tx)
        return True, "accepted"

    # ---------------- Blocks ----------------
    def make_candidate_block(self, proposer: str) -> Block:
        prev = self.chain[-1]
        txs = self.mempool[: self.cfg.max_txs_per_block]
        return Block(
            index=prev.index + 1,
            timestamp_ms=utc_ms(),
            transactions=txs,
            previous_hash=prev.block_hash,
            difficulty=self.cfg.difficulty,
            nonce=0,
            proposer=normalize_hex(proposer),
            block_hash="",
        )

    def mine_block(self, blk: Block, max_tries: int = 5_000_000) -> Tuple[bool, Block, int]:
        tries = 0
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
            return False, "invalid PoW"

        # snapshot accounts (no partial mutation)
        snapshot_accounts = {k: dict(v) for k, v in self.accounts.items()}

        for tx in blk.transactions:
            ok, why, sender = self.check_tx_rules(tx)
            if not ok or sender is None:
                self.accounts = snapshot_accounts
                return False, f"invalid tx in block: {why}"
            self.apply_tx(tx, sender)

        # optional issuance
        if self.cfg.block_reward > 0:
            prop = normalize_hex(blk.proposer)
            if is_address(prop):
                self.get_account(prop)["balance"] = int(self.get_account(prop)["balance"]) + int(self.cfg.block_reward)

        return True, "ok"

    def add_block(self, blk: Block) -> Tuple[bool, str]:
        ok, why = self.validate_block(blk)
        if not ok:
            return False, why

        # remove included txs
        included = set()
        for t in blk.transactions:
            ok_s, sender, _ = self.verify_sender(t)
            if ok_s:
                included.add((sender, t.nonce, t.timestamp_ms))

        new_mempool = []
        for t in self.mempool:
            ok_s, sender, _ = self.verify_sender(t)
            key = (sender, t.nonce, t.timestamp_ms) if ok_s else ("", t.nonce, t.timestamp_ms)
            if key not in included:
                new_mempool.append(t)
        self.mempool = new_mempool

        self.chain.append(blk)
        return True, "block appended"

    # ---------------- State export ----------------
    def chain_as_dict(self) -> Dict[str, Any]:
        return {
            "genesis_alloc": self.genesis_alloc,
            "chain": [b.to_dict() for b in self.chain],
            "mempool": [t.to_dict() for t in self.mempool],
            "accounts": self.accounts,
        }

    # ---------------- Sync helpers ----------------
    def replace_chain_if_better(self, new_chain: List[Block]) -> Tuple[bool, str]:
        """
        Longest chain wins, but with deterministic genesis state.
        """
        if len(new_chain) <= len(self.chain):
            return False, "not longer"

        tmp = Blockchain(self.cfg)
        tmp.set_genesis_alloc(self.genesis_alloc)
        tmp.reset_state_to_genesis()
        tmp.create_genesis()

        for blk in new_chain[1:]:
            ok, why = tmp.add_block(blk)
            if not ok:
                return False, f"new chain invalid: {why}"

        self.chain = tmp.chain
        self.mempool = tmp.mempool
        self.accounts = tmp.accounts
        return True, "chain replaced"
