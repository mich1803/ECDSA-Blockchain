const state = {
  nodeUrl: "",
  address: "",
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
  state.wallet = data.wallet;
  setText("node-url", `Node: ${data.node_url}`);
  setText("wallet-address", data.address);
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

async function init() {
  await loadInfo();
  await refreshMempool();
  await checkBalance();

  document.getElementById("send-tx").addEventListener("click", sendTx);
  document.getElementById("mine-block").addEventListener("click", mineBlock);
  document.getElementById("check-balance").addEventListener("click", checkBalance);

  setInterval(async () => {
    await refreshMempool();
  }, 5000);
}

init();
