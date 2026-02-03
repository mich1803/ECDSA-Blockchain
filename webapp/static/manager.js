const state = {
  settings: null,
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

async function refreshMempool() {
  const res = await fetch("/api/mempool");
  const data = await res.json();
  setText("mempool-size", `Mempool: ${data.mempool_size}`);
}

async function loadRequests() {
  const res = await fetch("/api/wallet-requests");
  const data = await res.json();
  const container = document.getElementById("wallet-requests");
  container.innerHTML = "";
  if (data.requests.length === 0) {
    container.textContent = "No requests yet.";
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
    container.textContent = "No accounts available.";
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
    container.textContent = "No transactions recorded.";
    return;
  }
  data.transactions.slice(-20).reverse().forEach((tx) => {
    const row = document.createElement("div");
    row.className = "list-row";
    row.textContent = `#${tx.block} ${tx.from} → ${tx.to.slice(0, 10)}... (${tx.value})`;
    container.appendChild(row);
  });
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
  setText("settings-result", data.ok ? "Settings saved." : "Error saving settings.");
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
  setText("genesis-result", data.ok ? `Genesis created (${data.accounts} accounts).` : data.msg);
}

async function init() {
  await loadSettings();
  await refreshMempool();
  await loadRequests();
  await loadAccounts();
  await loadLogs();

  document.getElementById("save-settings").addEventListener("click", saveSettings);
  document.getElementById("create-genesis").addEventListener("click", createGenesis);

  setInterval(async () => {
    await refreshMempool();
    await loadAccounts();
    await loadLogs();
  }, 5000);
}

init();
