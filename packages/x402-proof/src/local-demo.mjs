#!/usr/bin/env node
/** Optional, explicit-confirmation x402 Solana-devnet proof harness. */
import { spawn } from "node:child_process";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { base58 } from "@scure/base";
import { createMandate, generateEd25519KeyPair, signMandate, signRevocationList } from "@tiba/verifier";
import { executeMandatedX402Payment, x402Action } from "./mandated-payment.mjs";

const here = dirname(fileURLToPath(import.meta.url));
const root = resolve(here, "..", "..", "..");

function parseDotenv(text) {
  const env = {};
  for (const line of text.split(/\r?\n/)) {
    const match = line.match(/^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*?)\s*$/);
    if (!match) continue;
    const value = match[2];
    env[match[1]] = (value.startsWith('"') && value.endsWith('"')) || (value.startsWith("'") && value.endsWith("'")) ? value.slice(1, -1) : value;
  }
  return env;
}

async function waitForHealth(endpoint, child, stderr) {
  // This machine can be memory-constrained while Node resolves the x402 SDK.
  // Give the isolated loopback seller 30 seconds to load without retrying any
  // payment request.
  for (let attempt = 0; attempt < 120; attempt += 1) {
    if (child.exitCode !== null) throw new Error(`Local x402 seller exited before becoming healthy: ${stderr() || "no diagnostic"}`);
    try {
      const response = await fetch(`${endpoint}/health`);
      if (response.ok && (await response.json()).ok === true) return;
    } catch { /* Server is still starting. */ }
    await new Promise((resolvePromise) => setTimeout(resolvePromise, 250));
  }
  throw new Error(`Local x402 seller did not become healthy: ${stderr() || "no diagnostic"}`);
}

async function main() {
  if (process.env.TIBA_X402_CONFIRM !== "devnet") {
    throw new Error("Set TIBA_X402_CONFIRM=devnet before running this devnet-only x402 proof.");
  }
  const port = Number.parseInt(process.env.TIBA_X402_PORT ?? "4027", 10);
  if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error("TIBA_X402_PORT is invalid.");
  const walletFile = process.env.TIBA_PAYMENT_ENV_FILE ?? resolve(root, "..", "tiba", ".env");
  const wallet = parseDotenv(await readFile(walletFile, "utf8"));
  if (!wallet.SOLANA_PRIVATE_KEY || !wallet.SOLANA_ADDRESS) throw new Error("Devnet wallet configuration is incomplete.");
  const secret = base58.encode(Uint8Array.from(JSON.parse(wallet.SOLANA_PRIVATE_KEY)));
  const endpoint = `http://127.0.0.1:${port}/paid`;
  const seller = spawn(process.execPath, [resolve(here, "server.mjs")], {
    cwd: root,
    env: { ...process.env, TIBA_X402_PAY_TO: wallet.SOLANA_ADDRESS, TIBA_X402_PORT: String(port) },
    stdio: ["ignore", "ignore", "pipe"]
  });
  let sellerStderr = "";
  seller.stderr.on("data", (chunk) => { sellerStderr += chunk.toString(); });
  try {
    await waitForHealth(`http://127.0.0.1:${port}`, seller, () => sellerStderr.slice(-500).replace(/[\r\n]+/g, " "));
    const author = generateEd25519KeyPair();
    const agent = generateEd25519KeyPair();
    const action = x402Action({ endpoint });
    const now = new Date();
    const mandate = signMandate(createMandate({
      issuer: author.did, subject: agent.did, issued_at: now.toISOString(), expires_at: new Date(now.getTime() + 15 * 60 * 1000).toISOString(),
      scope: { actions: [{ protocol: action.protocol, action: action.action, resource: action.resource, tool: action.tool }], counterparties: [action.counterparty], data: { read: [], write: [] } },
      budget: { amount: "0.001", currency: "USDC", per_action_max: "0.001" }, delegation: { max_depth: 0 },
      revocation: { url: "https://tiba.invalid/revocations/x402-proof", list_id: "x402-proof", authority: author.did }, escalation: { mode: "notify" }
    }), author.privateKey);
    const revocationList = signRevocationList({
      type: "tiba.revocation_list", version: "0.1", id: `revocations:x402:${now.getTime()}`, issuer: author.did, list_id: "x402-proof", issued_at: now.toISOString(), revoked: []
    }, author.privateKey);
    const payment = await executeMandatedX402Payment({
      mandateChain: [mandate], agentPrivateKey: agent.privateKey, svmPrivateKey: secret, endpoint,
      revocationList, confirmation: "devnet"
    });
    if (!payment.ok) throw new Error("x402 payment was not settled.");
    const receiptDir = resolve(root, "demo", "receipts", `x402-run-${now.toISOString().replace(/[.:]/g, "-")}`);
    await mkdir(receiptDir, { recursive: true });
    await writeFile(resolve(receiptDir, "receipt-x402-payment.json"), `${JSON.stringify(payment.receipt, null, 2)}\n`, "utf8");
    await writeFile(resolve(receiptDir, "revocation-active.json"), `${JSON.stringify(revocationList, null, 2)}\n`, "utf8");
    await writeFile(resolve(receiptDir, "agent-public.did"), `${agent.did}\n`, "utf8");
    await writeFile(resolve(receiptDir, "x402-proof.json"), `${JSON.stringify(payment.proof, null, 2)}\n`, "utf8");
    console.log(JSON.stringify({ ok: true, receipt_dir: receiptDir, transaction_signature: payment.proof.transaction_signature, explorer_url: payment.proof.receipt_evidence.url }, null, 2));
  } finally {
    if (seller.exitCode === null) seller.kill();
  }
}

main().catch((error) => {
  console.error(error instanceof Error ? error.message : "TIBA_X402_PROOF_FAILED");
  process.exitCode = 1;
});
