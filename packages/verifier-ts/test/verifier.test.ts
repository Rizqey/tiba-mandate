import assert from "node:assert/strict";
import test from "node:test";
import {
  authorizeAction,
  createMandate,
  createReceipt,
  generateEd25519KeyPair,
  hashObject,
  signMandate,
  signReceipt,
  signRevocationList,
  verifyMandate,
  verifyMandateChain,
  verifyReceipt
} from "../src/index.ts";

const author = generateEd25519KeyPair();
const agent = generateEd25519KeyPair();
const now = new Date("2026-09-13T00:00:00.000Z");
const future = new Date("2030-09-20T00:00:00.000Z");

function root(overrides: Record<string, unknown> = {}) {
  return signMandate(createMandate({
    issuer: author.did,
    subject: agent.did,
    issued_at: "2026-09-12T00:00:00.000Z",
    expires_at: future.toISOString(),
    scope: {
      actions: [{ protocol: "mcp", action: "tools/call", resource: "notes.local", tool: "notes.write" }, { protocol: "payment", action: "transfer", resource: "solana:devnet", tool: "transfer_checked" }],
      counterparties: ["notes.local", "vendor-a"],
      data: { read: [], write: ["demo/notes"] }
    },
    budget: { amount: "2.00", currency: "USDC", per_action_max: "1.00" },
    delegation: { max_depth: 2 },
    revocation: { url: "https://example.invalid/revocations", list_id: "main", authority: author.did },
    escalation: { mode: "notify" },
    ...overrides
  }), author.privateKey);
}

const writeAction = { protocol: "mcp", action: "tools/call", resource: "notes.local", tool: "notes.write", counterparty: "notes.local", data_access: { read: [], write: ["demo/notes"] } };
const solanaEvidence = {
  type: "solana_transaction", network: "solana-devnet", reference: "3H2UQMcVZKQNSbb9cPL4gFzVdKv8gW2zwoWZzRRRx3iQxJysJ59qGzQK6KfbKzaU7mPUc7FZ4ccPa8VZmA8zFQ5G",
  url: "https://explorer.solana.com/tx/3H2UQMcVZKQNSbb9cPL4gFzVdKv8gW2zwoWZzRRRx3iQxJysJ59qGzQK6KfbKzaU7mPUc7FZ4ccPa8VZmA8zFQ5G?cluster=devnet"
};

test("creates and verifies signed mandate and receipt", () => {
  const mandate = root();
  assert.deepEqual(verifyMandate(mandate), { ok: true });
  const receipt = signReceipt(createReceipt({ mandate_chain: [mandate], action: writeAction, result: "success", actor: agent.did, input: { path: "a.txt" }, output: { ok: true } }), agent.privateKey);
  assert.deepEqual(verifyReceipt(receipt), { ok: true });
});

test("rejects tampered receipt", () => {
  const mandate = root();
  const receipt = signReceipt(createReceipt({ mandate_chain: [mandate], action: writeAction, result: "success", actor: agent.did, input: {}, output: {} }), agent.privateKey);
  receipt.result = "failure";
  assert.equal(verifyReceipt(receipt).ok, false);
});

test("blocks an expired mandate", () => {
  const mandate = root({ expires_at: "2026-09-12T23:59:59.000Z" });
  const check = authorizeAction({ mandate_chain: [mandate], action: writeAction, at: now });
  assert.equal(check.ok, false);
  if (!check.ok) assert.equal(check.code, "TIBA_EXPIRED");
});

test("blocks an over-budget action and accounts prior receipts", () => {
  const mandate = root();
  const payment = { protocol: "payment", action: "transfer", resource: "solana:devnet", tool: "transfer_checked", counterparty: "vendor-a", data_access: { read: [], write: [] }, amount: "1.01", currency: "USDC" };
  let check = authorizeAction({ mandate_chain: [mandate], action: payment, at: now });
  assert.equal(check.ok, false);
  if (!check.ok) assert.equal(check.code, "TIBA_BUDGET_EXCEEDED");
  const prior = signReceipt(createReceipt({ mandate_chain: [mandate], action: { ...payment, amount: "1.00" }, result: "success", actor: agent.did, input: {}, output: {}, evidence: [solanaEvidence] }), agent.privateKey);
  check = authorizeAction({ mandate_chain: [mandate], action: { ...payment, amount: "1.00" }, at: now, prior_receipts: [prior] });
  assert.equal(check.ok, true);
  check = authorizeAction({ mandate_chain: [mandate], action: { ...payment, amount: "0.01" }, at: now, prior_receipts: [prior, signReceipt(createReceipt({ mandate_chain: [mandate], action: { ...payment, amount: "1.00" }, result: "success", actor: agent.did, input: {}, output: {}, evidence: [solanaEvidence] }), agent.privateKey)] });
  assert.equal(check.ok, false);
});

test("rejects malformed timestamps, unknown nested fields, and unsupported payment evidence", () => {
  const mandate = root();
  const malformedTime = { ...mandate, issued_at: "2026-02-30T00:00:00.000Z" };
  const timeCheck = verifyMandate(malformedTime);
  assert.equal(timeCheck.ok, false);
  if (!timeCheck.ok) assert.equal(timeCheck.code, "TIBA_SCHEMA_INVALID");

  const unknownNested = { ...mandate, scope: { ...mandate.scope, data: { ...mandate.scope.data, unexpected: true } } };
  const nestedCheck = verifyMandate(unknownNested);
  assert.equal(nestedCheck.ok, false);
  if (!nestedCheck.ok) assert.equal(nestedCheck.code, "TIBA_SCHEMA_INVALID");

  const payment = { protocol: "payment", action: "transfer", resource: "solana:devnet", tool: "transfer_checked", counterparty: "vendor-a", data_access: { read: [], write: [] }, amount: "1.00", currency: "USDC" };
  assert.throws(() => signReceipt(createReceipt({ mandate_chain: [mandate], action: payment, result: "success", actor: agent.did, input: {}, output: {} }), agent.privateKey));
  assert.throws(() => signReceipt(createReceipt({ mandate_chain: [mandate], action: payment, result: "success", actor: agent.did, input: {}, output: {}, evidence: [{ ...solanaEvidence, url: "https://wrong.example/tx" }] }), agent.privateKey));
});

test("blocks a revoked mandate with signed revocation list", () => {
  const mandate = root();
  const list = signRevocationList({ type: "tiba.revocation_list", version: "0.1", id: "revocations:1", issuer: author.did, list_id: "main", issued_at: now.toISOString(), next_update: future.toISOString(), revoked: [{ mandate_id: mandate.id, revoked_at: now.toISOString() }] }, author.privateKey);
  const check = authorizeAction({ mandate_chain: [mandate], action: writeAction, at: now, revocation_list: list, require_revocation: true });
  assert.equal(check.ok, false);
  if (!check.ok) assert.equal(check.code, "TIBA_REVOKED");
});

test("rejects a sub-mandate that widens scope", () => {
  const parent = root();
  const childAgent = generateEd25519KeyPair();
  const child = signMandate(createMandate({
    issuer: agent.did,
    subject: childAgent.did,
    issued_at: now.toISOString(),
    expires_at: future.toISOString(),
    scope: { actions: [{ protocol: "mcp", action: "tools/call", resource: "notes.local", tool: "notes.delete" }], counterparties: ["notes.local"], data: { read: [], write: ["demo/notes"] } },
    delegation: { max_depth: 1, parent: { id: parent.id, hash: hashObject(parent) } },
    revocation: parent.revocation,
    escalation: parent.escalation
  }), agent.privateKey);
  const check = verifyMandateChain([parent, child]);
  assert.equal(check.ok, false);
  if (!check.ok) assert.equal(check.code, "TIBA_DELEGATION_WIDENED");
});
