import argparse

from minichain.crypto import generate_keypair, pubkey_from_hex, pubkey_to_address
from minichain.storage import write_json
from minichain.utils import Log


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--out", default="wallet.json")
    args = p.parse_args()

    kp = generate_keypair()

    pub = pubkey_from_hex(kp.public_key_hex)
    addr = pubkey_to_address(pub.format(compressed=False))

    write_json(args.out, {
        "private_key_hex": kp.private_key_hex,
        "public_key_hex": kp.public_key_hex,
        "address": addr,
    })
    Log.ok(f"Wallet created: {args.out}")
    Log.info(f"Address (20B hex): {addr}")
    Log.info(f"Public key (compressed hex): {kp.public_key_hex}")


if __name__ == "__main__":
    main()
