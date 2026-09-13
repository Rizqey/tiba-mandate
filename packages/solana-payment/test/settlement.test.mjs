import assert from "node:assert/strict";
import test from "node:test";
import { Keypair } from "@solana/web3.js";
import { createMandate, generateEd25519KeyPair, signMandate, signRevocationList } from "@tiba/verifier";
import {
  SOLANA_DEVNET_GENESIS_HASH,
  SOLANA_USDC_DEVNET_MINT,
  SolanaPaymentError,
  assertDevnetGenesisHash,
  buildSolanaPayoutTransaction,
  requireDevnet,
  solanaUsdcMint
} from "../src/settlement.mjs";
import { MandatedPaymentLedger, executeMandatedUsdcPayment, microsToUsdc, paymentAction } from "../src/mandated-payment.mjs";

test("devnet guard refuses any non-devnet configuration", () => {
  assert.throws(
    () => requireDevnet({ SOLANA_NETWORK: "mainnet-beta" }),
    (error) => error instanceof SolanaPaymentError && error.code === "SOLANA_NETWORK_NOT_DEVNET"
  );
  assert.throws(
    () => requireDevnet({ SOLANA_NETWORK: "devnet", SOLANA_CLUSTER: "mainnet-beta" }),
    (error) => error instanceof SolanaPaymentError && error.code === "SOLANA_NETWORK_NOT_DEVNET"
  );
});

test("devnet guard rejects a mainnet mint and non-devnet RPC genesis", () => {
  assert.throws(
    () => solanaUsdcMint({ SOLANA_USDC_MINT: Keypair.generate().publicKey.toBase58() }),
    (error) => error instanceof SolanaPaymentError && error.code === "SOLANA_MINT_NOT_DEVNET"
  );
  assert.doesNotThrow(() => assertDevnetGenesisHash(SOLANA_DEVNET_GENESIS_HASH));
  assert.throws(
    () => assertDevnetGenesisHash("mainnet-genesis"),
    (error) => error instanceof SolanaPaymentError && error.code === "SOLANA_NETWORK_NOT_DEVNET"
  );
});

test("transaction uses a memo, ATA creation, and TransferChecked", () => {
  const payer = Keypair.generate().publicKey;
  const recipient = Keypair.generate().publicKey.toBase58();
  const tx = buildSolanaPayoutTransaction([{ recipientAddress: recipient, amountMicros: 1_000n, intentId: "receipt-1" }], payer);
  assert.equal(tx.instructions.length, 3);
  assert.equal(tx.instructions[0].programId.toBase58(), "MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr");
});

test("transaction builder blocks invalid recipients and zero amounts", () => {
  const payer = Keypair.generate().publicKey;
  assert.throws(() => buildSolanaPayoutTransaction([{ recipientAddress: "invalid", amountMicros: 1n, intentId: "bad" }], payer));
  assert.throws(() => buildSolanaPayoutTransaction([{ recipientAddress: payer.toBase58(), amountMicros: 0n, intentId: "bad" }], payer));
});

test("payment action preserves exact USDC decimal amounts", () => {
  assert.equal(microsToUsdc(1_000n), "0.001");
  assert.equal(microsToUsdc(1_000_000n), "1");
  assert.equal(paymentAction({ recipientAddress: "payee", amountMicros: 10n }).amount, "0.00001");
});

test("local payment ledger serializes concurrent spend authorization", async () => {
  const author = generateEd25519KeyPair();
  const agent = generateEd25519KeyPair();
  const recipient = Keypair.generate().publicKey.toBase58();
  const mandate = signMandate(createMandate({
    issuer: author.did, subject: agent.did, issued_at: "2026-09-01T00:00:00.000Z", expires_at: "2030-09-20T00:00:00.000Z",
    scope: { actions: [{ protocol: "payment", action: "transfer", resource: "solana:devnet", tool: "transfer_checked" }], counterparties: [recipient], data: { read: [], write: [] } },
    budget: { amount: "0.001", currency: "USDC", per_action_max: "0.001" }, delegation: { max_depth: 0 },
    revocation: { url: "https://example.invalid/revocations", list_id: "main", authority: author.did }, escalation: { mode: "notify" }
  }), author.privateKey);
  const revocationList = signRevocationList({
    type: "tiba.revocation_list", version: "0.1", id: "revocations:payment", issuer: author.did, list_id: "main", issued_at: "2026-09-01T00:00:00.000Z", revoked: []
  }, author.privateKey);
  let settled = 0;
  const settle = async () => {
    settled += 1;
    await new Promise((resolve) => setTimeout(resolve, 10));
    const signature = "3H2UQMcVZKQNSbb9cPL4gFzVdKv8gW2zwoWZzRRRx3iQxJysJ59qGzQK6KfbKzaU7mPUc7FZ4ccPa8VZmA8zFQ5G";
    return { transaction_signature: signature, explorer_url: `https://explorer.solana.com/tx/${signature}?cluster=devnet`, network: "solana-devnet", mint: SOLANA_USDC_DEVNET_MINT, payer: recipient };
  };
  const ledger = new MandatedPaymentLedger();
  const options = { mandateChain: [mandate], agentPrivateKey: agent.privateKey, recipientAddress: recipient, amountMicros: 1_000n, revocationList, ledger, settle };
  const [first, second] = await Promise.all([
    executeMandatedUsdcPayment({ ...options, intentId: "one" }),
    executeMandatedUsdcPayment({ ...options, intentId: "two" })
  ]);
  assert.equal(first.ok, true);
  assert.equal(second.ok, false);
  assert.equal(second.receipt.result, "denied");
  assert.equal(settled, 1);
  assert.equal(ledger.priorReceipts.length, 1);
});
