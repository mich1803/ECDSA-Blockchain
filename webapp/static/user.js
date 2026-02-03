const state = {
  wallets: [],
  nodeUrl: "",
};

function setText(id, text) {
  document.getElementById(id).textContent = text;
}

async function loadSettings() {
  const res = await fetch("/api/settings");
  const data = await res.json();
  state.nodeUrl = data.node_url;
  document.getElementById("user-node-url").value = data.node_url;
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
  const res = await fetch(`/api/mempool?node_url=${encodeURIComponent(state.nodeUrl)}`);
  const data = await res.json();
  setText("mempool-size", `Mempool: ${data.mempool_size}`);
  setText("pending-blocks", data.mempool_size);
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
  setText("wallet-request-result", data.ok ? `Created ${data.wallet.filename}` : data.msg);
  await loadWallets();
}

async function sendTx() {
  const wallet = document.getElementById("sender-wallet").value;
  const to = document.getElementById("tx-to").value.trim();
  const amount = Number(document.getElementById("tx-amount").value);
  const res = await fetch("/api/tx", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ wallet, to, amount, node_url: state.nodeUrl }),
  });
  const data = await res.json();
  setText("tx-result", data.ok ? "Transaction submitted." : data.body || data.msg);
  await refreshMempool();
}

async function mineBlock() {
  const res = await fetch("/api/mine", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ node_url: state.nodeUrl }),
  });
  const data = await res.json();
  setText("mine-result", data.ok ? "Block mined." : data.body || "Error.");
  await refreshMempool();
}

async function checkBalance() {
  const wallet = document.getElementById("balance-wallet").value;
  const walletData = state.wallets.find((w) => w.filename === wallet);
  if (!walletData) {
    setText("balance-result", "Select a valid wallet.");
    return;
  }
  const res = await fetch(
    `/api/balance?address=${walletData.address}&node_url=${encodeURIComponent(state.nodeUrl)}`
  );
  const data = await res.json();
  setText("balance-result", `Balance: ${data.balance}`);
}

function saveNodeUrl() {
  const newUrl = document.getElementById("user-node-url").value.trim();
  if (!newUrl) {
    setText("user-node-result", "Node URL is required.");
    return;
  }
  state.nodeUrl = newUrl;
  setText("node-url", `Node: ${state.nodeUrl}`);
  setText("user-node-result", "Node URL updated.");
}

async function init() {
  await loadSettings();
  await loadWallets();
  await refreshMempool();

  document.getElementById("request-wallet").addEventListener("click", requestWallet);
  document.getElementById("send-tx").addEventListener("click", sendTx);
  document.getElementById("mine-block").addEventListener("click", mineBlock);
  document.getElementById("check-balance").addEventListener("click", checkBalance);
  document.getElementById("save-user-node").addEventListener("click", saveNodeUrl);

  setInterval(async () => {
    await refreshMempool();
  }, 5000);
}

init();
