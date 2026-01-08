![Minichain banner](media/header.jpg)
=================================================


This project implements an **educational blockchain** (toy blockchain) inspired by Ethereum, based on **ECDSA signatures (secp256k1)**. The goal is to study both the internal mechanics of a blockchain and real-world cryptographic and protocol vulnerabilities.

> **WARNING:** This repository is NOT intended for production use. All code is intentionally simple and, in some cases, deliberately insecure to demonstrate specific attacks.

---

## 1. Project Goals
The project focuses on four main objectives:

1.  **Understand basic blockchain operations**:
    * Transactions
    * Mempool
    * Blocks
    * Mining (Simplified Proof-of-Work)
    * Node synchronization
2.  **Understand ECDSA**:
    * Signing process
    * Public key recovery
    * The critical role of the nonce $k$
3.  **Demonstrate real attacks**:
    * Replay Attack
    * ECDSA Weak Nonce Attack (nonce reuse)
    * ECDSA Weak Nonce Attack (linear nonce)
4.  **Bridge the gap** between linear algebra, cryptography, and protocol security.

-------------------------------------------------
## 2. Repository Structure
-------------------------------------------------

.
├── README.md               (this file)
├── requirements.txt
├── .gitignore
│
├── wallets/                (JSON wallets with private keys)
│   ├── walletA.json
│   ├── walletB.json
│   └── walletC.json
│
├── data/                   (persistent node state)
│   └── node_<PORT>/state.json
│
├── minichain/              (core blockchain logic)
│   ├── crypto.py           (ECDSA, signing, recovery)
│   ├── chain.py            (blockchain rules)
│   ├── node.py             (HTTP node)
│   ├── paths.py            (wallets/ management)
│   └── ...
│
├── scripts/                (CLI scripts)
│   ├── create_wallet.py
│   ├── send_tx.py
│   ├── run_node_safe.py
│   ├── run_node_vuln.py
│   └── demo_scenario.py
│
└── attacks/                (attack scripts)
    ├── replay_attack.py
    └── weak_nonce/
        ├── make_weak_txs.py
        └── recover_privkey.py


-------------------------------------------------
## 3. Installation
-------------------------------------------------

Create a virtual environment:

```
python -m venv .venv
source .venv/bin/activate        (Linux / Mac)
.venv\Scripts\activate         (Windows)
```

Install dependencies:

```
pip install -r requirements.txt
```


-------------------------------------------------
## 4. Wallet
-------------------------------------------------

Wallets are saved in the folder: `wallets/`

Each wallet contains:
- ECDSA private key
- public key
- address (20 byte hex)

Create wallets:

```
python -m scripts.create_wallet --out walletA.json
python -m scripts.create_wallet --out walletB.json
python -m scripts.create_wallet --out walletC.json
```

Files are automatically created in `wallets/`.


-------------------------------------------------
## 5. Starting nodes (SAFE)
-------------------------------------------------

È possibile avviare più nodi sullo stesso PC usando porte diverse.

Nodo A (miner):

python -m scripts.run_node_safe --port 5001 --wallet walletA.json --genesis genesis.json --peers "http://127.0.0.1:5002,http://127.0.0.1:5003" --difficulty 2 

Nodo B:

python -m scripts.run_node_safe --port 5002 --wallet walletB.json --genesis genesis.json --peers "http://127.0.0.1:5001,http://127.0.0.1:5003" --difficulty 2

Nodo C:

python -m scripts.run_node_safe --port 5003 --wallet walletC.json --genesis genesis.json --peers "http://127.0.0.1:5001,http://127.0.0.1:5002" --difficulty 2


-------------------------------------------------
6. TRANSAZIONI NORMALI
-------------------------------------------------

Inviare una transazione:

python -m scripts.send_tx --node http://127.0.0.1:5001 --wallet walletA.json --to <WALLET_B> --amount 5

Minare un blocco:

curl.exe -X POST http://127.0.0.1:5001/mine -H "Content-Type: application/json" -d "{}"


-------------------------------------------------
7. DEMO SCENARIO AUTOMATICO
-------------------------------------------------

Simula:
- B -> A
- mining su A
- verifica sincronizzazione

python -m scripts.demo_scenario --nodeA http://127.0.0.1:5001 --nodeB http://127.0.0.1:5002 --nodeC http://127.0.0.1:5003 --amount 5


=================================================
ATTACCHI
=================================================

-------------------------------------------------
8. REPLAY ATTACK
-------------------------------------------------

Descrizione:
Un replay attack consiste nel reinviare IDENTICA una transazione firmata.
Se il protocollo non protegge nonce e duplicati, la stessa transazione
può essere accettata più volte.

Nel progetto il nodo vulnerabile:
- non verifica il nonce
- non incrementa il nonce
- accetta duplicati

Nodo A (vulnerabile):

python -m scripts.run_node_vuln --port 5001 --wallet walletA.json --genesis genesis.json --peers "http://127.0.0.1:5002,http://127.0.0.1:5003" --difficulty 2 --no-dedup

Nodo B (attaccante):

python -m scripts.run_node_safe --port 5002 --wallet walletB.json --genesis genesis.json --peers "http://127.0.0.1:5001,http://127.0.0.1:5003" --difficulty 2

Esecuzione attacco:

python -m attacks.replay_attack --nodeA http://127.0.0.1:5001 --nodeB http://127.0.0.1:5002 --amount 5 --replays 5

Risultato:
La stessa transazione viene applicata più volte, causando
trasferimenti ripetuti non autorizzati.


-------------------------------------------------
9. ECDSA WEAK NONCE – RIUSO
-------------------------------------------------

Descrizione:
Se due firme ECDSA usano lo stesso nonce k,
la chiave privata può essere recuperata.

Generare transazioni deboli:

python -m attacks.weak_nonce.make_weak_txs --node http://127.0.0.1:5001 --wallet walletA.json --to <WALLET_B> --amount 1 --mode reuse --outdir attacks/weak_nonce/out_reuse

Recuperare la chiave privata:

python -m attacks.weak_nonce.recover_privkey --mode reuse --tx attacks/weak_nonce/out_reuse/tx1.json attacks/weak_nonce/out_reuse/tx2.json


-------------------------------------------------
10. ECDSA WEAK NONCE – LINEARE
-------------------------------------------------

Descrizione:
Nonce generato come:
k = a*z + b  (mod n)

Con 3 firme è possibile risolvere il sistema
e recuperare la chiave privata.

Generazione:

python -m attacks.weak_nonce.make_weak_txs --node http://127.0.0.1:5001 --wallet walletA.json --to <WALLET_B> --amount 1 --mode linear --outdir attacks/weak_nonce/out_linear

Recupero chiave:

python -m attacks.weak_nonce.recover_privkey --mode linear --tx attacks/weak_nonce/out_linear/tx1.json attacks/weak_nonce/out_linear/tx2.json attacks/weak_nonce/out_linear/tx3.json


-------------------------------------------------
11. NOTE FINALI
-------------------------------------------------

ATTENZIONE:
- Wallet contengono chiavi private reali
- Codice volutamente insicuro
- Progetto solo per studio e didattica

Obiettivi didattici:
- capire ECDSA
- capire il ruolo del nonce
- osservare attacchi reali
- collegare algebra e sicurezza
