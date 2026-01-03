# attack/ – demo "secure vs vulnerable" nonce scenario

This folder adds **alternative entrypoints** so you can run:

- **SAFE node**: normal rules (nonce checked + nonce incremented)
- **VULNERABLE node**: simulated bug where the nonce is NOT enforced/consumed, enabling replay

Nothing in your original codebase needs to be edited: the vulnerable runner monkey-patches the rules at runtime.

---

## 1) Start 3 nodes (SAFE)

From repo root:

```bash
# Terminal 1
python -m attack.run_node_safe --port 5001 --wallet walletA.json --genesis genesis.json --peers "http://127.0.0.1:5002,http://127.0.0.1:5003" --difficulty 4 --block-reward 2

# Terminal 2
python -m attack.run_node_safe --port 5002 --wallet walletB.json --genesis genesis.json --peers "http://127.0.0.1:5001,http://127.0.0.1:5003" --difficulty 4 --block-reward 2

# Terminal 3
python -m attack.run_node_safe --port 5003 --wallet walletC.json --genesis genesis.json --peers "http://127.0.0.1:5001,http://127.0.0.1:5002" --difficulty 4 --block-reward 2
```

Try the replay attack:

```bash
python -m attack.replay_attack --nodeA http://127.0.0.1:5001 --nodeB http://127.0.0.1:5002 --amount 5 --replays 5
```

Expected: most replays are rejected (bad nonce / duplicate), balances look normal.

---

## 2) Start 3 nodes (VULNERABLE)

Stop nodes, then run the vulnerable entrypoint instead:

```bash
# Terminal 1
python -m attack.run_node_vuln --port 5001 --wallet walletA.json --genesis genesis.json --peers "http://127.0.0.1:5002,http://127.0.0.1:5003" --difficulty 4 --block-reward 2

# Terminal 2
python -m attack.run_node_vuln --port 5002 --wallet walletB.json --genesis genesis.json --peers "http://127.0.0.1:5001,http://127.0.0.1:5003" --difficulty 4 --block-reward 2

# Terminal 3
python -m attack.run_node_vuln --port 5003 --wallet walletC.json --genesis genesis.json --peers "http://127.0.0.1:5001,http://127.0.0.1:5002" --difficulty 4 --block-reward 2
```

Run the attack again:

```bash
python -m attack.replay_attack --nodeA http://127.0.0.1:5001 --nodeB http://127.0.0.1:5002 --amount 5 --replays 5
```

Expected: the *same signed tx* gets accepted multiple times and mined multiple times (replay),
so the final balances show an anomalous repeated transfer.

---

## Notes

- If your nodes persist state to disk, you may want to delete the per-port state files in `data/`
  between runs so balances start from genesis each time.
- `--mine-each` can be used to mine after each replay if your mempool happens to deduplicate.
