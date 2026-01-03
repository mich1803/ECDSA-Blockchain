ESPERIMENTI: ATTACCHI (SAFE vs VULN)
================================

Questa sezione descrive come eseguire esperimenti sugli attacchi usando la cartella `attack/`.
Gli esperimenti mostrano la differenza tra una blockchain “sicura” (SAFE) e una vulnerabile (VULN).

--------------------------------------------------
REQUISITI
--------------------------------------------------
Su TUTTI i nodi (stesso virtualenv):

pip install -r requirements.txt
pip install pycryptodome

Verifica:
python -c "from Crypto.Hash import keccak; print('keccak ok')"

--------------------------------------------------
RESET DELLO STATO (CONSIGLIATO)
--------------------------------------------------
Prima di ogni esperimento, riparti da uno stato pulito:

PowerShell:
Remove-Item -Force .\data\state_500*.json, .\data\mempool_500*.json

Oppure usa il flag:
--reset-state

--------------------------------------------------
ATTACCO 1: REPLAY ATTACK
--------------------------------------------------

IDEA
La stessa identica transazione firmata viene inviata più volte.
Se il nonce non viene controllato o incrementato, la blockchain accetta
più volte la stessa autorizzazione.

--------------------------------------------------
MODALITÀ SAFE (ATTACCO BLOCCATO)
--------------------------------------------------

Avvio nodi SAFE:

python -m attack.run_node_safe --port 5001 --wallet walletA.json --genesis genesis.json --difficulty 1 --reset-state --peers "http://<IP>:5002,http://<IP>:5003"
python -m attack.run_node_safe --port 5002 --wallet walletB.json --genesis genesis.json --difficulty 1 --reset-state --peers "http://<IP>:5001,http://<IP>:5003"
python -m attack.run_node_safe --port 5003 --wallet walletC.json --genesis genesis.json --difficulty 1 --reset-state --peers "http://<IP>:5001,http://<IP>:5002"

Lancio attacco:

python -m attack.replay_attack --nodeA http://<IP>:5001 --nodeB http://<IP>:5002 --amount 5 --replays 5

RISULTATO ATTESO (SAFE):
- replay rifiutati o marcati come "already seen"
- nel blocco entra UNA sola transazione
- bilanci coerenti con un solo trasferimento

--------------------------------------------------
MODALITÀ VULN (ATTACCO RIUSCITO)
--------------------------------------------------

Per rendere l’attacco efficace:
1) nonce non controllato
2) dedup disattivata sul miner (--no-dedup)
3) broadcast disattivato sull’attaccante (--no-broadcast)

Avvio nodi VULN:

Nodo A (miner):
python -m attack.run_node_vuln --port 5001 --wallet walletA.json --genesis genesis.json --difficulty 1 --reset-state --no-dedup --peers "http://<IP>:5002,http://<IP>:5003"

Nodo B (attacker):
python -m attack.run_node_vuln --port 5002 --wallet walletB.json --genesis genesis.json --difficulty 1 --reset-state --no-broadcast --peers "http://<IP>:5001,http://<IP>:5003"

Nodo C (opzionale):
python -m attack.run_node_vuln --port 5003 --wallet walletC.json --genesis genesis.json --difficulty 1 --reset-state --peers "http://<IP>:5001,http://<IP>:5002"

Lancio attacco:

python -m attack.replay_attack --nodeA http://<IP>:5001 --nodeB http://<IP>:5002 --amount 5 --replays 5

RISULTATO ATTESO (VULN):
- replay accettati più volte ("accepted")
- lo stesso blocco contiene più copie IDENTICHE della stessa transazione
- bilanci finali:
  A = A_iniziale + N * amount
  B = B_iniziale - N * amount
  (dove N = numero di replay + transazione originale)

--------------------------------------------------
NOTE CONCETTUALI (PER ESAME)
--------------------------------------------------

- L’address NON è dichiarativo: è derivato dalla public key.
- Il mittente di una transazione viene ricostruito dalla firma.
- Il nonce impone un ordine totale sulle transazioni di un account.
- Se il nonce non viene verificato o incrementato, nasce un replay attack.

--------------------------------------------------
TROUBLESHOOTING
--------------------------------------------------

Problema: vedo "already seen" anche in VULN
- il miner non ha --no-dedup
- l’attaccante ha broadcast attivo

Problema: insufficient funds ma genesis assegna 100
- l’address nel genesis NON coincide con quello derivato dalla public key

--------------------------------------------------
