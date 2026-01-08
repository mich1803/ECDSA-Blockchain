![Minichain banner](media/header.jpg)
=================================================

Questo progetto implementa una blockchain didattica (toy blockchain)
ispirata a Ethereum, basata su firme ECDSA (secp256k1), con l’obiettivo
di studiare sia il funzionamento interno di una blockchain sia alcune
vulnerabilità reali di tipo crittografico e di protocollo.

La repository NON è pensata per uso in produzione.
Tutto il codice è intenzionalmente semplice e in alcuni casi volutamente
insicuro per poter dimostrare gli attacchi.


-------------------------------------------------
1. OBIETTIVI DEL PROGETTO
-------------------------------------------------

Il progetto ha quattro obiettivi principali:

1) Comprendere il funzionamento base di una blockchain:
   - transazioni
   - mempool
   - blocchi
   - mining (Proof-of-Work semplificata)
   - sincronizzazione tra nodi

2) Capire come funziona ECDSA:
   - firma
   - recovery della chiave pubblica
   - ruolo critico del nonce k

3) Dimostrare attacchi reali:
   - Replay Attack
   - ECDSA Weak Nonce Attack (nonce riusato)
   - ECDSA Weak Nonce Attack (nonce lineare)

4) Collegare algebra lineare, crittografia e sicurezza dei protocolli


-------------------------------------------------
2. STRUTTURA DELLA REPOSITORY
-------------------------------------------------

.
├── README.txt              (questo file)
├── requirements.txt
├── .gitignore
│
├── wallets/                (wallet JSON con chiavi private)
│   ├── walletA.json
│   ├── walletB.json
│   └── walletC.json
│
├── data/                   (stato persistente dei nodi)
│   └── node_<PORT>/state.json
│
├── minichain/              (core blockchain)
│   ├── crypto.py           (ECDSA, firma, recovery)
│   ├── chain.py            (regole blockchain)
│   ├── node.py             (nodo HTTP)
│   ├── paths.py            (gestione wallets/)
│   └── ...
│
├── scripts/                (script CLI)
│   ├── create_wallet.py
│   ├── send_tx.py
│   ├── run_node_safe.py
│   ├── run_node_vuln.py
│   └── demo_scenario.py
│
└── attacks/                (attacchi)
    ├── replay_attack.py
    └── weak_nonce/
        ├── make_weak_txs.py
        └── recover_privkey.py


-------------------------------------------------
3. INSTALLAZIONE
-------------------------------------------------

Creare un ambiente virtuale:

python -m venv .venv
source .venv/bin/activate        (Linux / Mac)
.venv\Scripts\activate         (Windows)

Installare le dipendenze:

pip install -r requirements.txt


-------------------------------------------------
4. WALLET
-------------------------------------------------

I wallet sono salvati nella cartella:

wallets/

Ogni wallet contiene:
- chiave privata ECDSA
- chiave pubblica
- address (20 byte hex)

Creare i wallet:

python -m scripts.create_wallet --out walletA.json
python -m scripts.create_wallet --out walletB.json
python -m scripts.create_wallet --out walletC.json

I file vengono creati automaticamente in wallets/.


-------------------------------------------------
5. AVVIO DEI NODI (SAFE)
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
