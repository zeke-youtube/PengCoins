import net from "node:net";
import fs from "node:fs";
import path from "node:path";
import readline from "node:readline";
import { createHash, createPublicKey, verify } from "node:crypto";
import { fileURLToPath } from "node:url";

export const DIFFICULTY = 3; // Fixed testnet difficulty; not production-safe.
export const REWARD = 3;
const MAX_LINE = 1024 * 1024;
const hash = (value) => createHash("sha256").update(JSON.stringify(value)).digest("hex");
const fields = (b) => ({ index: b.index, previousHash: b.previousHash, timestamp: b.timestamp, miner: b.miner, transactions: b.transactions, nonce: b.nonce });
export const blockHash = (b) => hash(fields(b));
export const GENESIS = (() => {
  const b = { index: 0, previousHash: "0", timestamp: 0, miner: "", transactions: [], nonce: 0 };
  return Object.freeze({ ...b, hash: blockHash(b) });
})();

export function transactionPayload(tx) {
  return JSON.stringify({ from: tx.from, to: tx.to, amount: tx.amount, nonce: tx.nonce });
}
export function validTransaction(tx) {
  if (!tx || typeof tx !== "object" || typeof tx.from !== "string" || typeof tx.to !== "string" ||
      !Number.isSafeInteger(tx.amount) || tx.amount <= 0 ||
      !Number.isSafeInteger(tx.nonce) || tx.nonce < 0 ||
      typeof tx.signature !== "string") return false;
  try {
    const key = createPublicKey(tx.from);
    if (key.asymmetricKeyType !== "ed25519") return false;
    if (Buffer.from(tx.signature, "base64").toString("base64") !== tx.signature) return false;
    return verify(null, Buffer.from(transactionPayload(tx)), key, Buffer.from(tx.signature, "base64"));
  } catch { return false; }
}
function accountState(chain) {
  const balances = new Map(), nonces = new Map();
  const credit = (address, amount) => balances.set(address, (balances.get(address) || 0) + amount);
  for (const block of chain.slice(1)) {
    for (const tx of block.transactions) {
      credit(tx.from, -tx.amount);
      credit(tx.to, tx.amount);
      nonces.set(tx.from, tx.nonce);
    }
    credit(block.miner, REWARD);
  }
  return { balances, nonces, credit };
}
export function validateChain(chain) {
  if (!Array.isArray(chain) || !chain.length || JSON.stringify(chain[0]) !== JSON.stringify(GENESIS)) return false;
  const balances = new Map(), nonces = new Map();
  for (let i = 1; i < chain.length; i++) {
    const b = chain[i], prev = chain[i - 1];
    if (!b || b.index !== i || b.previousHash !== prev.hash ||
        !Number.isSafeInteger(b.timestamp) || b.timestamp < prev.timestamp ||
        b.timestamp > Date.now() + 120000 ||
        typeof b.miner !== "string" || !b.miner.length ||
        !Array.isArray(b.transactions) || b.transactions.length > 100 ||
        !Number.isSafeInteger(b.nonce) || b.nonce < 0 ||
        b.hash !== blockHash(b) || !b.hash.startsWith("0".repeat(DIFFICULTY))) return false;
    for (const tx of b.transactions) {
      if (!validTransaction(tx) || tx.nonce !== (nonces.get(tx.from) ?? -1) + 1 ||
          (balances.get(tx.from) || 0) < tx.amount) return false;
      balances.set(tx.from, balances.get(tx.from) - tx.amount);
      balances.set(tx.to, (balances.get(tx.to) || 0) + tx.amount);
      nonces.set(tx.from, tx.nonce);
    }
    balances.set(b.miner, (balances.get(b.miner) || 0) + REWARD);
  }
  return true;
}
export function mineBlock(chain, miner, transactions = []) {
  if (!validateChain(chain) || !miner) throw new Error("Invalid chain or miner address");
  const b = { index: chain.length, previousHash: chain.at(-1).hash,
    timestamp: Date.now(), miner, transactions, nonce: 0 };
  for (;;) {
    const candidate = { ...b, hash: blockHash(b) };
    if (candidate.hash.startsWith("0".repeat(DIFFICULTY))) {
      if (!validateChain([...chain, candidate])) throw new Error("Invalid transactions");
      return candidate;
    }
    b.nonce++;
  }
}
export function createNode({ file = "./data/chain.json" } = {}) {
  let chain = [GENESIS];
  if (fs.existsSync(file)) {
    chain = JSON.parse(fs.readFileSync(file, "utf8"));
    if (!validateChain(chain)) throw new Error("Stored blockchain is invalid");
  }
  let pending = [];
  const save = () => {
    fs.mkdirSync(path.dirname(file), { recursive: true });
    const tmp = file + ".tmp";
    fs.writeFileSync(tmp, JSON.stringify(chain, null, 2));
    fs.renameSync(tmp, file);
  };
  const addBlock = (block) => {
    if (!validateChain([...chain, block])) return false;
    chain.push(block);
    pending = pending.filter((tx) => !block.transactions.some((included) => included.signature === tx.signature));
    save();
    return true;
  };
  const addTransaction = (tx) => {
    if (!validTransaction(tx)) return false;
    const state = accountState(chain);
    const sameSender = pending.filter((t) => t.from === tx.from);
    const expectedNonce = (state.nonces.get(tx.from) ?? -1) + sameSender.length + 1;
    const reserved = sameSender.reduce((n, t) => n + t.amount, 0);
    if (tx.nonce !== expectedNonce || (state.balances.get(tx.from) || 0) - reserved < tx.amount) return false;
    pending.push(tx);
    return true;
  };
  return {
    get chain() { return structuredClone(chain); },
    get pending() { return structuredClone(pending); },
    balance(address) { return accountState(chain).balances.get(address) || 0; },
    addBlock, addTransaction
  };
}

export function startServer({ port = 3000, file = "./data/chain.json" } = {}) {
  const node = createNode({ file });
  const server = net.createServer((socket) => {
    socket.setEncoding("utf8");
    let buffer = "", greeted = false;
    const send = (message) => socket.write(JSON.stringify(message) + "\n");
    socket.on("data", (chunk) => {
      buffer += chunk;
      if (buffer.length > MAX_LINE) return socket.destroy();
      let end;
      while ((end = buffer.indexOf("\n")) !== -1) {
        const line = buffer.slice(0, end); buffer = buffer.slice(end + 1);
        let msg;
        try { msg = JSON.parse(line); } catch { send({ type: "ERROR", reason: "Bad JSON" }); continue; }
        if (msg?.type === "HELO") { greeted = true; send({ type: "HELO_ACK", height: node.chain.length - 1 }); continue; }
        if (!greeted) { send({ type: "ERROR", reason: "Send HELO first" }); continue; }
        switch (msg?.type) {
          case "PENG": send({ type: "PENG_ACK" }); break;
          case "GETCHAIN": send({ type: "CHAIN", blocks: node.chain }); break;
          case "BALANCE": send({ type: "BALANCE", amount: node.balance(msg.address) }); break;
          case "TX": send({ type: "TX_RESULT", accepted: node.addTransaction(msg.tx) }); break;
          case "BLOCK": send({ type: "BLOCK_RESULT", accepted: node.addBlock(msg.block) }); break;
          default: send({ type: "ERROR", reason: "Unknown command" });
        }
      }
    });
    socket.on("error", () => {});
  });
  server.listen(port, "127.0.0.1", () => console.log(`🐧 PengCoins node on 127.0.0.1:${port}`));
  return { server, node };
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const { node } = startServer({ port: Number(process.env.PORT || 3000), file: process.env.CHAIN_FILE || "./data/chain.json" });
  const cli = readline.createInterface({ input: process.stdin, output: process.stdout, prompt: "pengcoin> " });
  let mining = false;
  function mineNext() {
    if (!mining) return;
    const miner = process.env.PENG_MINER_ADDRESS;
    if (!miner) { console.log("Set PENG_MINER_ADDRESS first"); mining = false; return; }
    const block = mineBlock(node.chain, miner, node.pending);
    if (node.addBlock(block)) console.log(`⛏️ Mined block #${block.index}, reward ${REWARD} PENG`);
    setImmediate(mineNext);
  }
  console.log("Commands: start mine | stop mine | balance <address> | status | exit");
  cli.prompt();
  cli.on("line", (line) => {
    const cmd = line.trim();
    if (cmd === "start mine") {
      if (!mining) { mining = true; setImmediate(mineNext); }
      console.log("Mining:", mining ? "started" : "stopped");
    } else if (cmd === "stop mine") { mining = false; console.log("Mining stopped"); }
    else if (cmd.startsWith("balance ")) console.log(node.balance(cmd.slice(8)) + " PENG");
    else if (cmd === "status") console.log("Height:", node.chain.length - 1, "Pending:", node.pending.length);
    else if (cmd === "exit") { mining = false; process.exit(0); }
    else console.log("Unknown command");
    cli.prompt();
  });
}
