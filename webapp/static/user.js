const state = {
  nodeUrl: "",
  address: "",
  pubkey: "",
  wallet: "",
};

function setText(id, text) {
  document.getElementById(id).textContent = text;
}

async function loadInfo() {
  const res = await fetch("/api/info");
  const data = await res.json();
  state.nodeUrl = data.node_url;
  state.address = data.address;
  state.pubkey = data.pubkey;
  state.wallet = data.wallet;
  setText("node-url", `Node: ${data.node_url}`);
  setText("wallet-address", data.address);
  setText("wallet-pubkey", data.pubkey);
}

async function refreshMempool() {
  const res = await fetch("/api/mempool");
  const data = await res.json();
  setText("mempool-size", `Pending txs: ${data.mempool_size}`);
  setText("pending-blocks", data.mempool_size);
}

async function sendTx() {
  const to = document.getElementById("tx-to").value.trim();
  const amount = Number(document.getElementById("tx-amount").value);
  const res = await fetch("/api/tx", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ to, amount }),
  });
  const data = await res.json();
  setText("tx-result", data.ok ? "Transaction submitted." : data.body || data.msg);
  await refreshMempool();
}

async function mineBlock() {
  const res = await fetch("/api/mine", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({}),
  });
  const data = await res.json();
  setText("mine-result", data.ok ? "Block mined." : data.body || "Error.");
  await refreshMempool();
}

async function checkBalance() {
  const res = await fetch("/api/balance");
  const data = await res.json();
  if (data.balance !== undefined) {
    setText("wallet-balance", data.balance);
  }
}

function fillList(containerId, items, emptyText) {
  const container = document.getElementById(containerId);
  container.innerHTML = "";
  if (!items.length) {
    const empty = document.createElement("div");
    empty.className = "list-row state-empty";
    empty.textContent = emptyText;
    container.appendChild(empty);
    return;
  }
  items.forEach((item) => {
    const row = document.createElement("div");
    row.className = "list-row";
    row.textContent = item;
    container.appendChild(row);
  });
}

async function loadChainState() {
  const res = await fetch("/api/state");
  const data = await res.json();
  if (!data.ok) {
    setText("state-result", data.msg || "Failed to load chain state.");
    return;
  }
  const stateData = data.state || {};
  const genesis = Object.entries(stateData.genesis_alloc || {}).map(
    ([addr, amount]) => `${addr} · ${amount}`
  );
  const chain = (stateData.chain || []).map((block) => {
    const txCount = Array.isArray(block.transactions) ? block.transactions.length : 0;
    const hashLabel = block.hash ? `${block.hash.slice(0, 12)}...` : "n/a";
    const proposer = block.proposer ? block.proposer.slice(0, 12) + "..." : "n/a";
    return `#${block.index} · ${hashLabel} · txs: ${txCount} · diff: ${block.difficulty} · proposer: ${proposer}`;
  });
  const mempool = (stateData.mempool || []).map((tx) => {
    const to = tx.to ? tx.to.slice(0, 12) + "..." : "n/a";
    return `to: ${to} · value: ${tx.value} · nonce: ${tx.nonce}`;
  });
  const accounts = Object.entries(stateData.accounts || {}).map(
    ([addr, info]) => `${addr} · balance: ${info.balance} · nonce: ${info.nonce}`
  );

  fillList("state-genesis", genesis, "No genesis allocations.");
  fillList("state-chain", chain, "No blocks yet.");
  fillList("state-mempool", mempool, "Mempool is empty.");
  fillList("state-accounts", accounts, "No accounts loaded.");
  setText("state-result", "");
}

async function toggleChainState() {
  const container = document.getElementById("state-container");
  const button = document.getElementById("toggle-state");
  if (container.classList.contains("hidden")) {
    await loadChainState();
    container.classList.remove("hidden");
    button.textContent = "Hide chain state";
    return;
  }
  container.classList.add("hidden");
  button.textContent = "View chain state";
}

async function init() {
  await loadInfo();
  await refreshMempool();
  await checkBalance();

  document.getElementById("send-tx").addEventListener("click", sendTx);
  document.getElementById("mine-block").addEventListener("click", mineBlock);
  document.getElementById("toggle-state").addEventListener("click", toggleChainState);
  document.getElementById("check-balance").addEventListener("click", checkBalance);

  setInterval(async () => {
    await refreshMempool();
  }, 5000);
}

init();
