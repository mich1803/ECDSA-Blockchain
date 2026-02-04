import argparse
import json
from typing import Dict, List, Tuple

from minichain.paths import resolve_wallet_path, DEFAULT_WALLETS_DIR
from minichain.storage import read_json, write_json
from minichain.utils import Log, normalize_hex, is_address


def parse_alloc_item(item: str) -> Tuple[str, int]:
    if ":" not in item:
        raise ValueError(f"Invalid alloc entry '{item}'. Expected format wallet.json:amount")
    wallet_name, amount = item.split(":", 1)
    return wallet_name.strip(), int(amount)


def load_wallet_address(path: str) -> str:
    w = read_json(path)
    if not w or "address" not in w:
        raise ValueError(f"Wallet missing or invalid: {path}")
    addr = normalize_hex(w["address"])
    if not is_address(addr):
        raise ValueError(f"Invalid address in wallet: {path}")
    return addr


def build_alloc(
    alloc_items: List[str],
    alloc_json_path: str,
    wallets_dir: str,
) -> Dict[str, int]:
    alloc: Dict[str, int] = {}

    if alloc_json_path:
        data = read_json(alloc_json_path)
        if not isinstance(data, dict):
            raise ValueError("alloc json must be a dict of wallet filenames to amounts")
        for wallet_name, amount in data.items():
            wallet_path = resolve_wallet_path(wallet_name, wallets_dir)
            addr = load_wallet_address(wallet_path)
            alloc[addr] = int(amount)

    for item in alloc_items:
        wallet_name, amount = parse_alloc_item(item)
        wallet_path = resolve_wallet_path(wallet_name, wallets_dir)
        addr = load_wallet_address(wallet_path)
        alloc[addr] = int(amount)

    if not alloc:
        raise ValueError("No allocations provided. Use --alloc or --alloc-json.")

    return alloc


def main() -> None:
    p = argparse.ArgumentParser(description="Create a genesis.json from wallet files and balances.")
    p.add_argument("--out", default="genesis.json", help="Output genesis file path")
    p.add_argument("--wallets-dir", default=DEFAULT_WALLETS_DIR, help="Base directory for wallet files")
    p.add_argument(
        "--alloc",
        action="append",
        default=[],
        help="Allocation entry in form wallet.json:amount (repeatable)",
    )
    p.add_argument(
        "--alloc-json",
        default="",
        help="Path to JSON mapping of wallet filenames to amounts",
    )
    args = p.parse_args()

    alloc = build_alloc(args.alloc, args.alloc_json, args.wallets_dir)
    write_json(args.out, {"alloc": alloc})
    Log.ok(f"Genesis created at {args.out} with {len(alloc)} account(s)")


if __name__ == "__main__":
    main()
