import assert from "node:assert/strict";
import test from "node:test";
import { createMandate, generateEd25519KeyPair, signMandate, signRevocationList, verifyReceipt } from "@tiba/verifier";
import { executeMandatedX402Payment, x402Action } from "../src/mandated-payment.mjs";

const endpoint = "http://127.0.0.1:4021/paid";
const author = generateEd25519KeyPair();
const agent = generateEd25519KeyPair();
const action = x402Action({ endpoint });
const mandate = signMandate(createMandate({
  issuer: author.did, subject: agent.did, issued_at: "2026-09-01T00:00:00.000Z", expires_at: "2030-09-20T00:00:00.000Z",
  scope: { actions: [{ protocol: "x402", action: "http-get", resource: "x402:local", tool: "exact" }], counterparties: [action.counterparty], data: { read: [], write: [] } },
  budget: { amount: "0.001", currency: "USDC", per_action_max: "0.001" }, delegation: { max_depth: 0 },
  revocation: { url: "https://example.invalid/revocations", list_id: "x402", authority: author.did }, escalation: { mode: "notify" }
}), author.privateKey);
const revocationList = signRevocationList({
  type: "tiba.revocation_list", version: "0.1", id: "revocations:x402", issuer: author.did, list_id: "x402", issued_at: "2026-09-01T00:00:00.000Z", revoked: []
}, author.privateKey);
const transaction = "3H2UQMcVZKQNSbb9cPL4gFzVdKv8gW2zwoWZzRRRx3iQxJysJ59qGzQK6KfbKzaU7mPUc7FZ4ccPa8VZmA8zFQ5G";
const proof = {
  protocol: "x402", x402_network: "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1", payment_status: "settled", transaction_signature: transaction,
  receipt_evidence: { type: "solana_transaction", network: "solana-devnet", reference: transaction, url: `https://explorer.solana.com/tx/${transaction}?cluster=devnet` }
};

test("x402 settlement is covered by a Tiba receipt", async () => {
  const result = await executeMandatedX402Payment({
    mandateChain: [mandate], agentPrivateKey: agent.privateKey, svmPrivateKey: "runtime-only", endpoint,
    revocationList, confirmation: "devnet", pay: async () => proof
  });
  assert.equal(result.ok, true);
  assert.equal(result.receipt.result, "success");
  assert.deepEqual(result.receipt.evidence, [proof.receipt_evidence]);
  assert.equal(verifyReceipt(result.receipt).ok, true);
});

test("x402 payment refuses to run without signed revocation status", async () => {
  const result = await executeMandatedX402Payment({
    mandateChain: [mandate], agentPrivateKey: agent.privateKey, svmPrivateKey: "runtime-only", endpoint,
    confirmation: "devnet", pay: async () => proof
  });
  assert.equal(result.ok, false);
  assert.equal(result.receipt.result, "denied");
  assert.equal(result.receipt.reason, "TIBA_REVOCATION_UNAVAILABLE");
});
