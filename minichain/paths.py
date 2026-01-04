import os
from typing import Optional

DEFAULT_WALLETS_DIR = "wallets"


def ensure_dir(path: str) -> None:
    os.makedirs(path, exist_ok=True)


def resolve_wallet_path(wallet_arg: str, wallets_dir: str = DEFAULT_WALLETS_DIR) -> str:
    """
    Se wallet_arg è un path (contiene / o \\) lo usa com'è.
    Se è solo un nome file (es. walletA.json), lo cerca in wallets_dir.
    """
    if not wallet_arg:
        raise ValueError("wallet arg is empty")

    if ("/" in wallet_arg) or ("\\" in wallet_arg):
        return wallet_arg

    return os.path.join(wallets_dir, wallet_arg)


def default_wallet_path(filename: str, wallets_dir: str = DEFAULT_WALLETS_DIR) -> str:
    return os.path.join(wallets_dir, filename)
