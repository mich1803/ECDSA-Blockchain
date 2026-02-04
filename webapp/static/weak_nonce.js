function setText(id, text) {
  document.getElementById(id).textContent = text;
}

function fillList(containerId, items, emptyText) {
  const container = document.getElementById(containerId);
  container.innerHTML = "";
  if (!items.length) {
    const empty = document.createElement("div");
    empty.className = "list-row";
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

async function loadInfo() {
  const res = await fetch("/api/info");
  const data = await res.json();
  setText("node-url", `Node: ${data.node_url}`);
  setText("wallet-address", `Address: ${data.address}`);
}

function formatTx(tx, index) {
  const to = tx.to ? tx.to.slice(0, 12) + "..." : "n/a";
  const r = tx.signature?.r ? tx.signature.r.slice(0, 12) + "..." : "n/a";
  const s = tx.signature?.s ? tx.signature.s.slice(0, 12) + "..." : "n/a";
  return `#${index + 1} · to: ${to} · value: ${tx.value} · nonce: ${tx.nonce} · r: ${r} · s: ${s}`;
}

async function runAttack() {
  const address = document.getElementById("target-address").value.trim();
  const pubkey = document.getElementById("target-pubkey").value.trim();
  const res = await fetch("/api/recover", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ address, pubkey }),
  });
  const data = await res.json();
  if (!data.ok) {
    setText("attack-result", data.msg || "Attack failed.");
    fillList("log-list", data.logs || [], "No logs yet.");
    return;
  }
  setText("attack-result", "Recovered a key from reused nonce.");
  setText("recovered-key", data.recovered_key);
  setText("derived-address", data.derived_address);
  const logs = data.logs || [];
  const txRows = (data.txs || []).map(formatTx);
  fillList("log-list", [...logs, ...txRows], "No logs yet.");
}

async function init() {
  await loadInfo();
  document.getElementById("run-attack").addEventListener("click", runAttack);
}

init();
