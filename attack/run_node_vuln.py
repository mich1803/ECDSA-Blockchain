# attack/run_node_vuln.py
"""
Vulnerable node runner:
- nonce not enforced
- nonce not incremented
- duplicate txs allowed in mempool

NOTE:
To allow replay of the exact same tx over the network, you must also run nodes with:
  --no-dedup
because minichain/node.py can otherwise drop repeats at the HTTP layer.
"""

from minichain.chain import Blockchain


def patch_blockchain_vuln():
    # 1) Disable nonce equality check but keep other rules (signature + balance)
    def check_tx_rules_vuln(self, tx):
        from minichain.utils import normalize_hex, is_address

        if tx.value <= 0:
            return False, "value must be > 0", None

        to = normalize_hex(tx.to)
        if not is_address(to):
            return False, "invalid 'to' address", None

        ok, sender, why = self.recover_sender(tx)
        if not ok:
            return False, why, None

        acc = self.get_account(sender)

        # VULN: ignore nonce check completely (do not reject even if mismatch)
        bal = int(acc["balance"])
        if bal < tx.value:
            return False, f"insufficient funds (bal={bal}, need={tx.value})", None

        return True, "ok (nonce ignored)", sender

    Blockchain.check_tx_rules = check_tx_rules_vuln

    # 2) Do not increment nonce when applying tx
    def apply_tx_vuln(self, tx, sender_addr: str):
        from minichain.utils import normalize_hex

        sender = normalize_hex(sender_addr)
        receiver = normalize_hex(tx.to)

        sacc = self.get_account(sender)
        racc = self.get_account(receiver)

        sacc["balance"] = int(sacc["balance"]) - int(tx.value)
        racc["balance"] = int(racc["balance"]) + int(tx.value)
        # VULN: nonce not incremented

    Blockchain.apply_tx = apply_tx_vuln

    # 3) Allow duplicates in mempool (no (sender, nonce) duplicate rejection)
    def add_tx_to_mempool_vuln(self, tx):
        ok, why, sender = self.check_tx_rules(tx)
        if not ok or sender is None:
            return False, why
        self.mempool.append(tx)
        return True, "accepted (duplicates allowed)"

    Blockchain.add_tx_to_mempool = add_tx_to_mempool_vuln


def main():
    patch_blockchain_vuln()
    from minichain.node import run
    run()


if __name__ == "__main__":
    main()
