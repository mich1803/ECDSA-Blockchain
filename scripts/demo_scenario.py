"""
Demo scenario for 3 nodes in LAN or localhost:

1) Query public keys from nodes
2) Create a tx from node B to node A (using node B local signer endpoint)
3) Mine on node A
4) Show chain height on all nodes

Assumptions:
- Nodes are already running
- Node B has faucet coins or receives them first
"""

import argparse
import requests
from minichain.utils import Log


def get_identity(node: str):
    r = requests.get(node.rstrip("/") + "/identity", timeout=3)
    r.raise_for_status()
    return r.json()


def get_height(node: str):
    r = requests.get(node.rstrip("/") + "/identity", timeout=3)
    r.raise_for_status()
    return r.json()["height"]


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--nodeA", required=True, help="miner node url, e.g. http://127.0.0.1:5001")
    p.add_argument("--nodeB", required=True, help="client node url, e.g. http://127.0.0.1:5002")
    p.add_argument("--nodeC", required=True, help="validator node url, e.g. http://127.0.0.1:5003")
    p.add_argument("--amount", type=int, default=5)
    args = p.parse_args()

    A = args.nodeA.rstrip("/")
    B = args.nodeB.rstrip("/")
    C = args.nodeC.rstrip("/")

    ida = get_identity(A)
    idb = get_identity(B)
    idc = get_identity(C)

    Log.info(f"A pub={ida['public_key_hex']}")
    Log.info(f"B pub={idb['public_key_hex']}")
    Log.info(f"C pub={idc['public_key_hex']}")

    # B -> A transaction
    Log.info("Creating TX from B -> A")
    r = requests.post(B + "/local/make_tx", json={
        "receiver_pubkey": ida["public_key_hex"],
        "amount": args.amount
    }, timeout=5)
    print(r.status_code, r.text)
    if r.status_code != 200:
        Log.warn("TX creation failed. Ensure B has enough balance (use --faucet on nodeB).")
        return

    # Mine on A
    Log.info("Mining on node A")
    r = requests.post(A + "/mine", json={}, timeout=30)
    print(r.status_code, r.text)
    if r.status_code != 200:
        Log.warn("Mining failed (mempool empty or difficulty too high).")
        return

    # Check heights
    ha, hb, hc = get_height(A), get_height(B), get_height(C)
    Log.ok(f"Heights: A={ha} B={hb} C={hc}")
    Log.info("If heights differ, call /sync on the lagging node(s).")


if __name__ == "__main__":
    main()
