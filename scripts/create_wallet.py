import argparse
import os

from minichain.crypto import generate_keypair, pubkey_from_hex, pubkey_to_address
from minichain.storage import write_json
from minichain.utils import Log
from minichain.paths import ensure_dir, resolve_wallet_path, DEFAULT_WALLETS_DIR


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--out", default="wallet.json", help="filename or path. If filename only, saved under wallets/")
    p.add_argument("--wallets-dir", default=DEFAULT_WALLETS_DIR, help="base dir for wallet files")
    args = p.parse_args()

    ensure_dir(args.wallets_dir)

    out_path = resolve_wallet_path(args.out, args.wallets_dir)

    kp = generate_keypair()
    pub = pubkey_from_hex(kp.public_key_hex)
    addr = pubkey_to_address(pub.format(compressed=False))

    write_json(out_path, {
        "private_key_hex": kp.private_key_hex,
        "public_key_hex": kp.public_key_hex,
        "address": addr,
    })

    Log.ok(f"Wallet created: {out_path}")
    Log.info(f"Address (20B hex): {addr}")
    Log.info(f"Public key (compressed hex): {kp.public_key_hex}")


if __name__ == "__main__":
    main()
