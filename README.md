# Mini-Blockchain (3 nodes) with ECDSA secp256k1

Authors: Michele Magrini, Francesco Marrocco, Leo Petrarca

This repo contains a didactic mini-blockchain that runs on 3 computers (or 3 terminals).
It uses:
- ECDSA signatures on secp256k1 (Bitcoin-style curve)
- Signed transactions
- Block chaining with SHA-256
- Light Proof-of-Work (PoW) for a “mining” demo
- Peer-to-peer propagation via HTTP (Flask)



## 1) Setup


Requirements:
- Python 3.10+ recommended
- 3 machines in the same LAN (or use localhost with 3 ports)

Install:
    pip install -r requirements.txt

If `coincurve` fails to install, it’s usually a platform/build issue.
Tell me your OS + Python version and I’ll provide a fallback.

## 2) Create wallets (one per node)


On each machine (or once, then copy files):

    python scripts/create_wallet.py --out walletA.json
    python scripts/create_wallet.py --out walletB.json
    python scripts/create_wallet.py --out walletC.json

Each wallet JSON contains:
- private_key_hex
- public_key_hex (compressed secp256k1 pubkey)


## 3) Run 3 nodes


Choose three ports (example: 5001, 5002, 5003).
Each node knows its peers via --peers.

Node A (miner) on PC1:

    python -m run_node --port 5001 --wallet walletA.json --genesis genesis.json --peers "http://PC_1_ID:5002,http://PC_1_ID:5003" --block-reward 0

Node B (client) on PC2

Give B some initial coins too (for easy demo):

    python -m run_node --port 5002 --wallet walletB.json --genesis genesis.json --peers "http://PC_2_ID:5001,http://PC_2_ID:5003" --block-reward 0

Node C (validator) on PC3:

    python -m run_node --port 5003 --wallet walletC.json --genesis genesis.json --peers "http://PC_3_ID:5002,http://PC_3_ID:5001" --block-reward 0


If you are testing on ONE machine, use localhost peers:
- Node A peers: http://127.0.0.1:5002,http://127.0.0.1:5003
- Node B peers: http://127.0.0.1:5001,http://127.0.0.1:5003
- Node C peers: http://127.0.0.1:5001,http://127.0.0.1:5002

## 4) Check the nodes


Open in browser or curl:
- GET /identity  -> public key, height, peers
- GET /state     -> chain + mempool + balances
- GET /chain     -> chain only

Example:

    curl http://PC1_IP:5001/identity
    curl http://PC1_IP:5001/state

## 5) Create and send a signed transaction


Option A (recommended): let the node compute the nonce

Use Node B to create+sign locally and broadcast:

    python scripts/send_tx.py --node http://PC2_IP:5002 --wallet walletB.json --to <PUBKEY_A> --amount 5

When --nonce is omitted, it calls POST /local/make_tx which:
- computes the next nonce for that sender
- signs the tx
- broadcasts it to peers

Option B: manually specify a nonce

    python scripts/send_tx.py --node http://PC2_IP:5002 --wallet walletB.json --to <PUBKEY_A> --amount 5 --nonce 0

## 6) Mine a block (PoW light)

On Node A:

    curl -X POST http://PC1_IP:5001/mine -H "Content-Type: application/json" -d "{}"

If mining is too slow, lower difficulty when starting nodes:

    python run_node.py --port 5001 --wallet walletA.json --difficulty 3 ...


## 7) Sync if needed


If a node missed a broadcast:
    curl -X POST http://PC3_IP:5003/sync -H "Content-Type: application/json" -d "{}"

## 8) Nice outputs for the exam

Each node writes artifacts to its data/ folder:
- data/chain_<port>.json   (chain + mempool + balances)
- data/mempool_<port>.json

You can show:
- accepted/rejected transactions with reason
- mined blocks with tries and hash prefix 0000...
- final chain state as JSON (easy to screenshot)

## 9) Demo script (optional)

Once nodes are running:

    python scripts/demo_scenario.py --nodeA http://PC1_IP:5001 --nodeB http://PC2_IP:5002 --nodeC http://PC3_IP:5003 --amount 5

## 10) How to write the final project (suggested structure)

A) Theory (Math + Crypto)
1. Elliptic curves over finite fields: E(F_p) and group law
2. secp256k1 parameters: why y^2 = x^3 + 7 (mod p) and prime-order subgroup
3. ECDSA:
   - keygen: Q = dG
   - signing: (r,s) = (x(kG) mod n, k^{-1}(H(m)+rd) mod n)
   - verification: u1G + u2Q check
4. Security:
   - ECDLP intuition
   - why nonce reuse breaks ECDSA (mention RFC 6979)

B) System design (Blockchain)
1. Data model: Transaction / Block
2. Hash chaining: integrity
3. Mempool: pending transactions
4. PoW (light): educational mining
5. P2P propagation: broadcast to peers
6. Validation rules: signature, hash, prev_hash, PoW, nonce ordering, balances

C) Experiments (what to show)
1. Happy path: B->A tx, mined block, same height on all nodes
2. Tampering: modify tx after signing -> rejected
3. Replay: reuse nonce -> rejected
4. Optional: change difficulty and measure mining tries/time

D) Results
- Timing (mining tries, signature verify time)
- Screenshots/logs
- JSON chain outputs


## 11) Troubleshooting

- “insufficient funds”: start the sender node with --faucet
- mining too slow: lower --difficulty
- nodes out of sync: call /sync
- port blocked: ensure LAN firewall allows chosen ports


If you want, I can also provide:
- a minimal web dashboard to visualize blocks/txs,
- a Merkle tree extension,
- or an ECDSA “nonce reuse” attack demo on a small toy curve (safe for teaching).
