import assert from "node:assert/strict";
import { mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { createMandate, generateEd25519KeyPair, signMandate, signRevocationList, verifyReceipt } from "@tiba/verifier";
import { McpGuard } from "../src/guard.mjs";

const author = generateEd25519KeyPair();
const agent = generateEd25519KeyPair();
function issueMandate({ budget } = {}) {
  return signMandate(createMandate({
    issuer: author.did, subject: agent.did, issued_at: "2026-09-12T00:00:00.000Z", expires_at: "2030-09-20T00:00:00.000Z",
    scope: { actions: [{ protocol: "mcp", action: "tools/call", resource: "notes.local", tool: "notes.write" }], counterparties: ["notes.local"], data: { read: [], write: ["demo/notes"] } },
    ...(budget ? { budget } : {}),
    delegation: { max_depth: 0 }, revocation: { url: "https://example.invalid/revocations", list_id: "main", authority: author.did }, escalation: { mode: "notify" }
  }), author.privateKey);
}

const mandate = issueMandate();
const revocationList = signRevocationList({
  type: "tiba.revocation_list", version: "0.1", id: "revocations:test", issuer: author.did, list_id: "main",
  issued_at: "2026-09-12T00:00:00.000Z", revoked: []
}, author.privateKey);

test("guard permits scoped MCP calls and signs receipts", async () => {
  let downstream = 0;
  const guard = new McpGuard({
    mandateChain: [mandate], agentPrivateKey: agent.privateKey, revocationList, receiptDir: await mkdtemp(join(tmpdir(), "tiba-guard-")), serverId: "notes.local",
    toolPolicy: { "notes.write": { write: ["demo/notes"] } },
    callTool: async (name, args) => {
      downstream += 1;
      return { name, args, content: [{ type: "text", text: "ok" }], _meta: { upstream: "preserved" } };
    }
  });
  const result = await guard.call("notes.write", { path: "hello.txt", text: "hello" });
  assert.equal(result.isError, false);
  assert.equal(downstream, 1);
  assert.equal(verifyReceipt(result.receipt).ok, true);
  assert.equal(result.output._meta.upstream, "preserved");
  assert.deepEqual(result.output._meta["org.tiba/receipt"], result.receipt);
});

test("guard blocks out-of-scope call before downstream and signs denied receipt", async () => {
  let downstream = 0;
  const guard = new McpGuard({
    mandateChain: [mandate], agentPrivateKey: agent.privateKey, revocationList, receiptDir: await mkdtemp(join(tmpdir(), "tiba-guard-")), serverId: "notes.local",
    toolPolicy: { "notes.write": { write: ["demo/notes"] } },
    callTool: async () => { downstream += 1; return {}; }
  });
  const result = await guard.call("notes.delete", { path: "hello.txt" });
  assert.equal(result.isError, true);
  assert.equal(result.error.code, "TIBA_SCOPE_DENIED");
  assert.equal(downstream, 0);
  assert.equal(verifyReceipt(result.receipt).ok, true);
  assert.equal(result.output.isError, true);
  assert.deepEqual(result.output._meta["org.tiba/receipt"], result.receipt);
});

test("guard fails closed when no signed revocation list is available", async () => {
  let downstream = 0;
  const guard = new McpGuard({
    mandateChain: [mandate], agentPrivateKey: agent.privateKey, receiptDir: await mkdtemp(join(tmpdir(), "tiba-guard-")), serverId: "notes.local",
    toolPolicy: { "notes.write": { write: ["demo/notes"] } },
    callTool: async () => { downstream += 1; return {}; }
  });
  const result = await guard.call("notes.write", { path: "hello.txt", text: "hello" });
  assert.equal(result.isError, true);
  assert.equal(result.error.code, "TIBA_REVOCATION_UNAVAILABLE");
  assert.equal(downstream, 0);
});

test("guard serializes concurrent budgeted calls before spending remaining budget", async () => {
  let downstream = 0;
  const budgetedMandate = issueMandate({ budget: { amount: "1.00", currency: "USDC", per_action_max: "1.00" } });
  const guard = new McpGuard({
    mandateChain: [budgetedMandate], agentPrivateKey: agent.privateKey, revocationList, receiptDir: await mkdtemp(join(tmpdir(), "tiba-guard-")), serverId: "notes.local",
    toolPolicy: { "notes.write": { write: ["demo/notes"], amount: "1.00", currency: "USDC" } },
    callTool: async () => {
      downstream += 1;
      await new Promise((resolve) => setTimeout(resolve, 15));
      return { content: [{ type: "text", text: "spent" }] };
    }
  });

  const [first, second] = await Promise.all([
    guard.call("notes.write", { path: "one.txt", text: "one" }),
    guard.call("notes.write", { path: "two.txt", text: "two" })
  ]);

  assert.equal(first.isError, false);
  assert.equal(second.isError, true);
  assert.equal(second.error.code, "TIBA_BUDGET_EXCEEDED");
  assert.equal(downstream, 1);
  assert.equal(guard.priorReceipts.length, 1);
});

test("guard returns a signed successful result when audit receipt persistence fails", async () => {
  const temporary = await mkdtemp(join(tmpdir(), "tiba-guard-"));
  const receiptDirFile = join(temporary, "not-a-directory");
  await writeFile(receiptDirFile, "receipt directory deliberately blocked", "utf8");
  let downstream = 0;
  const guard = new McpGuard({
    mandateChain: [mandate], agentPrivateKey: agent.privateKey, revocationList, receiptDir: receiptDirFile, serverId: "notes.local",
    toolPolicy: { "notes.write": { write: ["demo/notes"] } },
    callTool: async () => {
      downstream += 1;
      return { content: [{ type: "text", text: "upstream success" }] };
    }
  });

  const result = await guard.call("notes.write", { path: "audit.txt", text: "still succeeds" });
  assert.equal(result.isError, false);
  assert.equal(downstream, 1);
  assert.equal(verifyReceipt(result.receipt).ok, true);
  assert.equal(result.auditPersistenceError.code, "TIBA_AUDIT_PERSISTENCE_FAILED");
  assert.deepEqual(result.output._meta["org.tiba/receipt"], result.receipt);
});
