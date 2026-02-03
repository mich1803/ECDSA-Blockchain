const state = {
  settings: null,
  wallets: [],
};

function setText(id, text) {
  document.getElementById(id).textContent = text;
}

async function loadSettings() {
  const res = await fetch("/api/settings");
  const data = await res.json();
  state.settings = data;
  document.getElementById("settings-node").value = data.node_url;
  document.getElementById("settings-difficulty").value = data.difficulty;
  document.getElementById("settings-reward").value = data.block_reward;
  setText("node-url", `Node: ${data.node_url}`);
}

async function loadWallets() {
  const res = await fetch("/api/wallets");
  const data = await res.json();
  state.wallets = data.wallets;
  const selects = [document.getElementById("sender-wallet"), document.getElementById("balance-wallet")];
  selects.forEach((sel) => {
    sel.innerHTML = "";
    data.wallets.forEach((w) => {
      const opt = document.createElement("option");
      opt.value = w.filename;
      opt.textContent = `${w.filename} (${w.address.slice(0, 8)}...)`;
      sel.appendChild(opt);
    });
  });
}

async function refreshMempool() {
  const res = await fetch("/api/mempool");
  const data = await res.json();
  setText("mempool-size", `Mempool: ${data.mempool_size}`);
  setText("pending-blocks", data.mempool_size);
}

async function loadRequests() {
  const res = await fetch("/api/wallet-requests");
  const data = await res.json();
  const container = document.getElementById("wallet-requests");
  container.innerHTML = "";
  if (data.requests.length === 0) {
    container.textContent = "Nessuna richiesta.";
    return;
  }
  data.requests.forEach((req) => {
    const row = document.createElement("div");
    row.className = "list-row";
    row.textContent = `${req.filename} → ${req.address} (${req.amount})`;
    container.appendChild(row);
  });
}

async function loadAccounts() {
  const res = await fetch("/api/accounts");
  const data = await res.json();
  const container = document.getElementById("accounts");
  container.innerHTML = "";
  if (data.accounts.length === 0) {
    container.textContent = "Nessun account disponibile.";
    return;
  }
  data.accounts.forEach((acc) => {
    const row = document.createElement("div");
    row.className = "list-row";
    row.textContent = `${acc.wallet}: ${acc.balance}`;
    container.appendChild(row);
  });
}

async function loadLogs() {
  const res = await fetch("/api/logs");
  const data = await res.json();
  const container = document.getElementById("tx-log");
  container.innerHTML = "";
  if (data.transactions.length === 0) {
    container.textContent = "Nessuna transazione registrata.";
    return;
  }
  data.transactions.slice(-20).reverse().forEach((tx) => {
    const row = document.createElement("div");
    row.className = "list-row";
    row.textContent = `#${tx.block} ${tx.from} → ${tx.to.slice(0, 10)}... (${tx.value})`;
    container.appendChild(row);
  });
}

async function requestWallet() {
  const name = document.getElementById("wallet-name").value;
  const amount = Number(document.getElementById("wallet-amount").value);
  const res = await fetch("/api/wallets/request", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ name, amount }),
  });
  const data = await res.json();
  setText("wallet-request-result", data.ok ? `Creato ${data.wallet.filename}` : data.msg);
  await loadWallets();
  await loadRequests();
}

async function sendTx() {
  const wallet = document.getElementById("sender-wallet").value;
  const to = document.getElementById("tx-to").value.trim();
  const amount = Number(document.getElementById("tx-amount").value);
  const res = await fetch("/api/tx", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ wallet, to, amount }),
  });
  const data = await res.json();
  setText("tx-result", data.ok ? "Transazione inviata" : data.body || data.msg);
  await refreshMempool();
}

async function mineBlock() {
  const res = await fetch("/api/mine", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({}),
  });
  const data = await res.json();
  setText("mine-result", data.ok ? "Blocco minato" : data.body || "Errore");
  await refreshMempool();
  await loadAccounts();
  await loadLogs();
}

async function checkBalance() {
  const wallet = document.getElementById("balance-wallet").value;
  const walletData = state.wallets.find((w) => w.filename === wallet);
  if (!walletData) {
    setText("balance-result", "Seleziona un wallet valido");
    return;
  }
  const res = await fetch(`/api/balance?address=${walletData.address}`);
  const data = await res.json();
  setText("balance-result", `Saldo: ${data.balance}`);
}

async function saveSettings() {
  const payload = {
    node_url: document.getElementById("settings-node").value,
    difficulty: Number(document.getElementById("settings-difficulty").value),
    block_reward: Number(document.getElementById("settings-reward").value),
  };
  const res = await fetch("/api/settings", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
  const data = await res.json();
  setText("settings-result", data.ok ? "Impostazioni salvate" : "Errore");
  await loadSettings();
}

async function createGenesis() {
  const genesisPath = document.getElementById("genesis-path").value;
  const res = await fetch("/api/genesis", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ genesis_path: genesisPath }),
  });
  const data = await res.json();
  setText("genesis-result", data.ok ? `Genesis creato (${data.accounts} account)` : data.msg);
}

async function init() {
  await loadSettings();
  await loadWallets();
  await refreshMempool();
  await loadRequests();
  await loadAccounts();
  await loadLogs();

  document.getElementById("request-wallet").addEventListener("click", requestWallet);
  document.getElementById("send-tx").addEventListener("click", sendTx);
  document.getElementById("mine-block").addEventListener("click", mineBlock);
  document.getElementById("check-balance").addEventListener("click", checkBalance);
  document.getElementById("save-settings").addEventListener("click", saveSettings);
  document.getElementById("create-genesis").addEventListener("click", createGenesis);

  setInterval(async () => {
    await refreshMempool();
    await loadAccounts();
    await loadLogs();
  }, 5000);
}

init();
