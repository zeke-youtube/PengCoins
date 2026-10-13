import test from "node:test";
import assert from "node:assert/strict";
import { generateKeyPairSync, sign } from "node:crypto";
import { GENESIS, mineBlock, validateChain, createNode, transactionPayload } from "../src/server.js";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";

test("real PoW reward, signed transfer, and no overspending", () => {
  const dir = mkdtempSync(path.join(tmpdir(), "pengcoins-"));
  try {
    const node = createNode({ file: path.join(dir, "chain.json") });
    const alice = generateKeyPairSync("ed25519");
    const bob = generateKeyPairSync("ed25519");
    const from = alice.publicKey.export({ type: "spki", format: "pem" });
    const to = bob.publicKey.export({ type: "spki", format: "pem" });
    assert.equal(node.addBlock(mineBlock(node.chain, from)), true);
    assert.equal(node.balance(from), 3);
    const tx = { from, to, amount: 2, nonce: 0 };
    tx.signature = sign(null, Buffer.from(transactionPayload(tx)), alice.privateKey).toString("base64");
    assert.equal(node.addTransaction(tx), true);
    assert.equal(node.addTransaction(tx), false);
    assert.equal(node.addBlock(mineBlock(node.chain, from, node.pending)), true);
    assert.equal(node.balance(to), 2);
    assert.equal(node.balance(from), 4);
    assert.equal(validateChain(node.chain), true);
    const forged = node.chain;
    forged[1].miner = to;
    assert.equal(validateChain(forged), false);
    const reloaded = createNode({ file: path.join(dir, "chain.json") });
    assert.equal(reloaded.balance(to), 2);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});
test("genesis cannot be replaced", () => {
  assert.equal(validateChain([GENESIS]), true);
  assert.equal(validateChain([{ ...GENESIS, miner: "attacker" }]), false);
});
