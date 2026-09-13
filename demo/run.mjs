#!/usr/bin/env node
/**
 * Tiba's complete devnet-only v0 story. It intentionally needs two explicit
 * confirmations: SIGN for the human mandate review and TIBA_DEMO_CONFIRM_DEVNET=YES
 * before any devnet USDC is broadcast.
 */
import { spawn } from "node:child_process";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { Keypair } from "@solana/web3.js";
import {
  generateEd25519KeyPair,
  keyPairFromPrivatePem,
  signRevocationList
} from "@tiba/verifier";
import { McpGuard } from "@tiba/mcp-guard/src/guard.mjs";
import { StdioMcpClient } from "@tiba/mcp-guard/src/stdio-client.mjs";
import { MandatedPaymentLedger, executeMandatedUsdcPayment } from "@tiba/solana-payment/mandated-payment";
import { SOLANA_DEVNET_RPC, SOLANA_USDC_DEVNET_MINT } from "@tiba/solana-payment";
import { loadEnvFile } from "@tiba/policy-author";

const here = dirname(fileURLToPath(import.meta.url));
const root = resolve(here, "..");
const runtimeDir = resolve(here, ".runtime");
const runId = new Date().toISOString().replace(/[.:]/g, "-");
const receiptDir = resolve(here, "receipts", `run-${runId}`);
const notesDir = resolve(runtimeDir, `notes-${runId}`);
const mandatePath = resolve(runtimeDir, `mandate-${runId}.json`);
const authorKeyPath = resolve(runtimeDir, `policy-author-${runId}.key.json`);

function fail(message) {
  throw new Error(message);
}

async function ensure(path) {
  await mkdir(path, { recursive: true });
}

async function writeJson(path, value) {
  await writeFile(path, `${JSON.stringify(value, null, 2)}\n`, "utf8");
}

async function runInteractivePolicyAuthor({ subject, payee, expiresAt }) {
  const script = resolve(root, "packages", "policy-author", "src", "cli.mjs");
  const args = [
    script,
    "--instruction", "Allow this demo agent one local notes write and one 0.001 USDC Solana devnet transfer to the named demo payee. No other actions.",
    "--subject", subject,
    "--issuer-key-file", authorKeyPath,
    "--expires-at", expiresAt,
    "--out", mandatePath,
    "--provider", "offline",
    "--offline-demo",
    "--counterparty", payee
  ];
  await new Promise((resolvePromise, reject) => {
    const child = spawn(process.execPath, args, { cwd: root, stdio: "inherit" });
    child.once("error", reject);
    child.once("exit", (code) => code === 0 ? resolvePromise() : reject(new Error(`Policy author exited with ${code}.`)));
  });
}

function statusList({ author, mandate, revoked = [] }) {
  const now = new Date();
  const nextUpdate = new Date(now.getTime() + 15 * 60 * 1000);
  return signRevocationList({
    type: "tiba.revocation_list",
    version: "0.1",
    id: `revocations:${runId}:${revoked.length}`,
    issuer: author.did,
    list_id: mandate.revocation.list_id,
    issued_at: now.toISOString(),
    next_update: nextUpdate.toISOString(),
    revoked
  }, author.privateKey);
}

async function independentVerify(trustedActor) {
  const pythonRoot = resolve(root, "packages", "verifier-py");
  const pythonPath = process.env.PYTHONPATH ? `${pythonRoot};${process.env.PYTHONPATH}` : pythonRoot;
  const result = await new Promise((resolvePromise, reject) => {
    const child = spawn("python", ["-m", "tiba_verifier.cli", "--receipts-dir", receiptDir, "--trusted-actor", trustedActor], {
      cwd: root,
      env: { ...process.env, PYTHONPATH: pythonPath },
      stdio: ["ignore", "pipe", "pipe"]
    });
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (chunk) => { stdout += chunk; });
    child.stderr.on("data", (chunk) => { stderr += chunk; });
    child.once("error", reject);
    child.once("exit", (code) => code === 0 ? resolvePromise(stdout.trim()) : reject(new Error(stderr.trim() || stdout.trim() || `Independent verifier exited with ${code}.`)));
  });
  return JSON.parse(result);
}

function safeSettlementEnv(source) {
  if (!source.SOLANA_PRIVATE_KEY) fail("The existing Tiba devnet wallet is unavailable: SOLANA_PRIVATE_KEY is not set.");
  return {
    SOLANA_NETWORK: "devnet",
    SOLANA_PRIVATE_KEY: source.SOLANA_PRIVATE_KEY,
    ...(source.SOLANA_ADDRESS ? { SOLANA_ADDRESS: source.SOLANA_ADDRESS } : {}),
    // Do not inherit a user-configured RPC or mint. The payment module checks
    // devnet genesis as a second defense; this makes the demo's intent explicit.
    SOLANA_RPC_URL: SOLANA_DEVNET_RPC,
    SOLANA_USDC_MINT: SOLANA_USDC_DEVNET_MINT
  };
}

async function main() {
  if (process.env.TIBA_DEMO_CONFIRM_DEVNET !== "YES") {
    fail("Refusing to broadcast. Re-run with TIBA_DEMO_CONFIRM_DEVNET=YES after reviewing the devnet-only flow.");
  }
  await ensure(runtimeDir);
  await ensure(receiptDir);
  const agent = generateEd25519KeyPair();
  const payee = Keypair.generate().publicKey.toBase58();
  const expiresAt = new Date(Date.now() + 60 * 60 * 1000).toISOString();

  console.log("\n1/6 Policy author: review the generated mandate and type SIGN.");
  await runInteractivePolicyAuthor({ subject: agent.did, payee, expiresAt });
  const mandate = JSON.parse(await readFile(mandatePath, "utf8"));
  const authorStored = JSON.parse(await readFile(authorKeyPath, "utf8"));
  const author = keyPairFromPrivatePem(authorStored.private_key_pem);
  const activeList = statusList({ author, mandate });
  await writeJson(resolve(receiptDir, "revocation-active.json"), activeList);
  await writeFile(resolve(receiptDir, "agent-public.did"), `${agent.did}\n`, "utf8");

  const client = new StdioMcpClient(process.execPath, [resolve(root, "packages", "mcp-guard", "src", "local-notes-server.mjs")], {
    cwd: root,
    env: { ...process.env, TIBA_NOTES_DIR: notesDir }
  });
  await client.start();
  try {
    const guard = new McpGuard({
      mandateChain: [mandate],
      agentPrivateKey: agent.privateKey,
      revocationList: activeList,
      receiptDir: resolve(receiptDir, "guard-internal"),
      serverId: "notes.local",
      toolPolicy: { "notes.write": { resource: "notes.local", counterparty: "notes.local", write: ["demo/notes"] } },
      callTool: (name, args) => client.callTool(name, args)
    });

    console.log("2/6 Allowed MCP note write.");
    const allowed = await guard.call("notes.write", { path: "demo/notes/allowed.txt", text: "Tiba signed this allowed MCP action." });
    if (allowed.isError) fail(`Allowed MCP call unexpectedly failed: ${allowed.error.code}`);
    await writeJson(resolve(receiptDir, "receipt-01-mcp-allowed.json"), allowed.receipt);

    console.log("3/6 Blocked out-of-scope MCP call.");
    const blocked = await guard.call("notes.delete", { path: "demo/notes/allowed.txt" });
    if (!blocked.isError || blocked.error.code !== "TIBA_SCOPE_DENIED") fail("Out-of-scope MCP call was not denied.");
    await writeJson(resolve(receiptDir, "receipt-02-mcp-blocked.json"), blocked.receipt);

    console.log("4/6 Allowed 0.001 USDC payment on Solana devnet.");
    const paymentEnvPath = process.env.TIBA_PAYMENT_ENV_FILE ?? resolve(root, "..", "tiba", ".env");
    const paymentEnv = safeSettlementEnv(await loadEnvFile(paymentEnvPath));
    const payment = await executeMandatedUsdcPayment({
      mandateChain: [mandate], agentPrivateKey: agent.privateKey, recipientAddress: payee, amountMicros: 1_000n,
      revocationList: activeList, ledger: new MandatedPaymentLedger(), env: paymentEnv, intentId: `tiba-demo-${runId}`
    });
    await writeJson(resolve(receiptDir, "receipt-03-solana-payment.json"), payment.receipt);
    if (!payment.ok) fail(`Devnet payment did not complete: ${payment.receipt.result}.`);

    console.log("5/6 Revoking the mandate and refusing a fourth action.");
    const revokedAt = new Date().toISOString();
    const revokedList = statusList({ author, mandate, revoked: [{ mandate_id: mandate.id, revoked_at: revokedAt, reason: "demo complete" }] });
    await writeJson(resolve(receiptDir, "revocation-revoked.json"), revokedList);
    guard.revocationList = revokedList;
    const revoked = await guard.call("notes.write", { path: "demo/notes/after-revocation.txt", text: "This must never be written." });
    if (!revoked.isError || revoked.error.code !== "TIBA_REVOKED") fail("Revoked mandate action was not denied.");
    await writeJson(resolve(receiptDir, "receipt-04-revoked.json"), revoked.receipt);

    console.log("6/6 Separate Python verifier checks only public did:key + receipts.");
    const independent = await independentVerify(agent.did);
    if (!independent.ok || independent.verified_receipts.length !== 4) fail("Independent receipt verification failed.");
    await writeJson(resolve(receiptDir, "independent-verification.json"), independent);
    await writeJson(resolve(receiptDir, "manifest.json"), {
      run_id: runId,
      trusted_actor: agent.did,
      mandate_id: mandate.id,
      receipt_files: independent.verified_receipts,
      devnet_transaction_signature: payment.settlement.transaction_signature,
      devnet_explorer_url: payment.settlement.explorer_url
    });
    await writeFile(resolve(here, "RUN.md"), `# Tiba demo transcript\n\nRun: \`${runId}\`\n\n1. The policy-author CLI rendered a narrow draft and received \`SIGN\` before writing the mandate.\n2. The MCP guard allowed one scoped local note write and signed a receipt.\n3. The MCP guard blocked \`notes.delete\` before forwarding it and signed a denied receipt.\n4. The payment guard sent 0.001 USDC on Solana devnet under the mandate. Transaction: [${payment.settlement.transaction_signature}](${payment.settlement.explorer_url}).\n5. A signed revocation list revoked the mandate; a fourth action was refused with \`TIBA_REVOKED\`.\n6. A separate Python process received only the agent public \`did:key\` and receipt files, and verified all four receipts.\n\nArtifacts: [receipts/run-${runId}](receipts/run-${runId})\n`, "utf8");
    console.log(`\nComplete. Public artifacts: ${receiptDir}`);
  } finally {
    await client.stop();
  }
}

main().catch((error) => {
  console.error(error instanceof Error ? error.message : error);
  process.exitCode = 1;
});
