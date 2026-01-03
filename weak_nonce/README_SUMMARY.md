Comandi rapidi (riassunto)
=========================

# 0) venv + deps
python -m venv .venv
# activate ...
pip install -r requirements.txt

# 1) wallet
python -m create_wallet --out wallet_node.json
python -m create_wallet --out wallet_victim.json
python -m create_wallet --out wallet_attacker.json

# 2) start node (terminal 1)
python -m run_node --port 5001 --wallet wallet_node.json --faucet --faucet-amount 200 --difficulty 2

# 3) fund victim (terminal 2)
python -m send_tx --node http://127.0.0.1:5001 --wallet wallet_node.json --to VICTIM_ADDR --amount 50
curl -X POST http://127.0.0.1:5001/mine -H "Content-Type: application/json" -d "{}"

# 4) weak tx (reuse)
python -m weak_nonce.make_weak_txs --node http://127.0.0.1:5001 --wallet wallet_victim.json --to ATTACKER_ADDR --amount 1 --mode reuse --outdir attacks/reuse
curl.exe -X POST http://127.0.0.1:5001/mine -H "Content-Type: application/json" -d "{}"

# 5) recover
python -m weak_nonce.recover_privkey --mode reuse --tx attacks/reuse/tx1.json attacks/reuse/tx2.json

# 6) forge: create wallet_victim_compromised.json from recovered key, then:
python -m send_tx --node http://127.0.0.1:5001 --wallet wallet_victim_compromised.json --to ATTACKER_ADDR --amount 10
curl -X POST http://127.0.0.1:5001/mine -H "Content-Type: application/json" -d "{}"
