WEAK NONCE (ECDSA k) — Demo completo per l’esame
===============================================

Questa cartella ti permette di dimostrare *praticamente* un attacco a ECDSA (secp256k1) quando la nonce
ECDSA `k` è scelta male.

⚠️ Importante: qui NON parliamo della `nonce` della transazione (account nonce stile Ethereum), ma della
nonce interna a ECDSA (`k`), che deve essere imprevedibile e mai riusata.

Contenuto
---------
- make_weak_txs.py
  Genera e invia transazioni firmate con `k` debole (firme recoverable v,r,s compatibili col tuo nodo).
  Modalità:
    - reuse  : stesso k su 2 firme  -> basta 2 tx
    - linear : k = a*z + b (mod n)  -> bastano 3 tx (sistema lineare)

- recover_privkey.py
  Recupera la chiave privata della vittima dai file JSON delle transazioni:
    - --mode reuse  (2 tx)
    - --mode linear (3 tx)

Scenario d’esame (single-node) — checklist
------------------------------------------
Obiettivo: mostrare che un attaccante, osservando 2/3 transazioni firmate con nonce ECDSA debole,
recupera la private key della vittima e poi firma una transazione “rubando” i fondi.

Nel seguito usiamo 3 wallet:
- wallet_node.json     (wallet del nodo, con faucet per avere fondi iniziali)
- wallet_victim.json   (vittima)
- wallet_attacker.json (attaccante / destinatario)

Tutti i comandi vanno eseguiti dalla ROOT del repository (dove ci sono run_node.py, create_wallet.py, ecc.).

0) Setup ambiente
-----------------
Linux/macOS:
  python3 -m venv .venv
  source .venv/bin/activate
  pip install -r requirements.txt

Windows PowerShell:
  py -m venv .venv
  .venv\Scripts\Activate.ps1
  pip install -r requirements.txt

1) Crea i wallet
----------------
  python -m create_wallet --out wallet_node.json
  python -m create_wallet --out wallet_victim.json
  python -m create_wallet --out wallet_attacker.json

Annotati gli address stampati a terminale:
- NODE_ADDR
- VICTIM_ADDR
- ATTACKER_ADDR

(Se vuoi ristamparli velocemente:)
  python - <<'PY'
import json
for fn in ["wallet_node.json","wallet_victim.json","wallet_attacker.json"]:
    w=json.load(open(fn))
    print(fn, "->", w["address"])
PY

2) Avvia il nodo (Terminale #1)
-------------------------------
Esempio su localhost:5001 (faucet dà fondi al wallet del nodo):
  python -m run_node --port 5001 --wallet wallet_node.json --faucet --faucet-amount 200 --difficulty 2 --block-reward 0

Lascia questo terminale aperto.

3) Finanza la vittima (Terminale #2)
------------------------------------
Invia 50 coin dal nodo alla vittima e mina:
  python -m send_tx --node http://127.0.0.1:5001 --wallet wallet_node.json --to VICTIM_ADDR --amount 50
  curl -X POST http://127.0.0.1:5001/mine -H "Content-Type: application/json" -d "{}"

Controlla balance e nonce della vittima:
  curl http://127.0.0.1:5001/balance/VICTIM_ADDR
  curl http://127.0.0.1:5001/nonce/VICTIM_ADDR

A questo punto la vittima ha fondi e può fare transazioni.

===========================================================
ATTACCO A) RIUSO DI k (2 transazioni con stesso r)
===========================================================

4A) Genera 2 transazioni “deboli” dalla vittima (Terminale #2)
--------------------------------------------------------------
Queste transazioni sono firmate con lo STESSO k (quindi stesso r) e vengono inviate al nodo.
I file tx_*.json vengono salvati in outdir (qui: attacks/reuse).

  python weak_nonce/make_weak_txs.py ^
    --node http://127.0.0.1:5001 ^
    --wallet wallet_victim.json ^
    --to ATTACKER_ADDR ^
    --amount 1 ^
    --mode reuse ^
    --outdir attacks/reuse

Linux/macOS (stesso comando, senza ^):
  python weak_nonce/make_weak_txs.py \
    --node http://127.0.0.1:5001 \
    --wallet wallet_victim.json \
    --to ATTACKER_ADDR \
    --amount 1 \
    --mode reuse \
    --outdir attacks/reuse

Poi mina per includerle in un blocco:
  curl -X POST http://127.0.0.1:5001/mine -H "Content-Type: application/json" -d "{}"

5A) Recupera la chiave privata della vittima dai 2 file (Terminale #2)
----------------------------------------------------------------------
  python weak_nonce/recover_privkey.py --mode reuse --tx attacks/reuse/tx_0.json attacks/reuse/tx_1.json --pubkey $(python - <<'PY'
import json; print(json.load(open("wallet_victim.json"))["public_key_hex"])
PY
)

Su Windows PowerShell (senza $(...)):
  $pub=(python - <<'PY'
import json; print(json.load(open("wallet_victim.json"))["public_key_hex"])
PY
)
  python weak_nonce/recover_privkey.py --mode reuse --tx attacks/reuse/tx_0.json attacks/reuse/tx_1.json --pubkey $pub

Output: vedrai “Recovered private key x = 0x....” (questa è la private key della vittima!).

6A) Crea un wallet “compromised” con la chiave recuperata (Terminale #2)
------------------------------------------------------------------------
Sostituisci 0x... con l’hex stampato (può iniziare con 0x).
  python - <<'PY'
import json
from minichain.crypto import pubkey_from_hex, pubkey_to_address
from coincurve import PrivateKey

RECOVERED = "0xPUT_RECOVERED_KEY_HERE"
x = int(RECOVERED, 16)
priv_hex = x.to_bytes(32,"big").hex()
pk = PrivateKey(bytes.fromhex(priv_hex))
pub_hex = pk.public_key.format(compressed=True).hex()
addr = pubkey_to_address(pk.public_key.format(compressed=False))
json.dump({"private_key_hex": priv_hex, "public_key_hex": pub_hex, "address": addr},
          open("wallet_victim_compromised.json","w"), indent=2)
print("written wallet_victim_compromised.json ->", addr)
PY

7A) Dimostra l’impatto: firma una tx come la vittima e “ruba” i fondi (Terminale #2)
-----------------------------------------------------------------------------------
Ora l’attaccante può spendere i fondi della vittima senza avere wallet_victim.json.

Esempio: manda 10 coin all’attaccante:
  python -m send_tx --node http://127.0.0.1:5001 --wallet wallet_victim_compromised.json --to ATTACKER_ADDR --amount 10
  curl -X POST http://127.0.0.1:5001/mine -H "Content-Type: application/json" -d "{}"

Verifica:
  curl http://127.0.0.1:5001/balance/VICTIM_ADDR
  curl http://127.0.0.1:5001/balance/ATTACKER_ADDR

===========================================================
ATTACCO B) NONCE LINEARE (k = a*z + b) — sistema lineare
===========================================================

4B) Genera 3 transazioni “deboli” (Terminale #2)
------------------------------------------------
  python weak_nonce/make_weak_txs.py ^
    --node http://127.0.0.1:5001 ^
    --wallet wallet_victim.json ^
    --to ATTACKER_ADDR ^
    --amount 1 ^
    --mode linear ^
    --outdir attacks/linear

Mina:
  curl -X POST http://127.0.0.1:5001/mine -H "Content-Type: application/json" -d "{}"

5B) Recupera la chiave privata via sistema lineare (Terminale #2)
-----------------------------------------------------------------
  $pub=(python - <<'PY'
import json; print(json.load(open("wallet_victim.json"))["public_key_hex"])
PY
)
  python weak_nonce/recover_privkey.py --mode linear --tx attacks/linear/tx_0.json attacks/linear/tx_1.json attacks/linear/tx_2.json --pubkey $pub

Otterrai anche a e b (solo per didattica) + la private key x.

6B) Riusa i passi 6A e 7A per creare wallet_victim_compromised.json e dimostrare la frode.

Troubleshooting rapido
----------------------
- “mempool empty” su /mine:
  non ci sono tx pendenti. Rigenera le tx o invia una tx normale.

- “invalid nonce” o “bad nonce”:
  la tx.nonce di account deve essere esattamente quella che il nodo si aspetta.
  make_weak_txs.py la legge dal nodo via /nonce/<addr>, quindi:
   - controlla di usare il nodo giusto
   - controlla che la vittima non abbia già inviato altre tx in mezzo

- “insufficient balance”:
  finanzia di più la vittima dal wallet_node e mina.

- Multi-node:
  per l’esame consiglio single-node (più robusto). Se vuoi multi-node coerente, usa --genesis su TUTTI i nodi
  invece di --faucet (che è locale).

