import argparse
from minichain.crypto import generate_keypair
from minichain.storage import write_json
from minichain.utils import Log


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--out", default="wallet.json")
    args = p.parse_args()

    kp = generate_keypair()
    write_json(args.out, {
        "private_key_hex": kp.private_key_hex,
        "public_key_hex": kp.public_key_hex
    })
    Log.ok(f"Wallet created: {args.out}")
    Log.info(f"Public key (compressed hex): {kp.public_key_hex}")


if __name__ == "__main__":
    main()
