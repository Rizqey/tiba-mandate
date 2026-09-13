import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtemp, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { createMandate, createReceipt, generateEd25519KeyPair, signMandate, signReceipt, verifyReceipt } from "@tiba/verifier";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const pythonRoot = resolve(root, "packages", "verifier-py");

function python(args) {
  const result = spawnSync("python", args, { cwd: root, env: { ...process.env, PYTHONPATH: pythonRoot }, encoding: "utf8" });
  assert.equal(result.status, 0, result.stderr || result.stdout);
  return result.stdout;
}

function issueTsReceipt() {
  const author = generateEd25519KeyPair();
  const agent = generateEd25519KeyPair();
  const mandate = signMandate(createMandate({
    issuer: author.did, subject: agent.did, issued_at: "2026-09-01T00:00:00.000Z", expires_at: "2030-09-20T00:00:00.000Z",
    scope: { actions: [{ protocol: "mcp", action: "tools/call", resource: "notes.local", tool: "notes.write" }], counterparties: ["notes.local"], data: { read: [], write: ["notes"] } },
    delegation: { max_depth: 0 }, revocation: { url: "https://example.invalid/revocations", list_id: "interop", authority: author.did }, escalation: { mode: "notify" }
  }), author.privateKey);
  const receipt = signReceipt(createReceipt({
    mandate_chain: [mandate], action: { protocol: "mcp", action: "tools/call", resource: "notes.local", tool: "notes.write", counterparty: "notes.local", data_access: { read: [], write: ["notes"] } },
    result: "success", actor: agent.did, input: { note: "interoperable" }, output: { ok: true }
  }), agent.privateKey);
  return { receipt, actor: agent.did };
}

test("Python independently verifies a receipt signed by TypeScript", async () => {
  const directory = await mkdtemp(join(tmpdir(), "tiba-ts-to-py-"));
  const { receipt, actor } = issueTsReceipt();
  await writeFile(join(directory, "receipt-ts.json"), JSON.stringify(receipt), "utf8");
  const output = python(["-m", "tiba_verifier.cli", "--receipts-dir", directory, "--trusted-actor", actor]);
  assert.match(output, /"ok":true/);
});

test("TypeScript independently verifies a receipt signed by Python", async () => {
  const directory = await mkdtemp(join(tmpdir(), "tiba-py-to-ts-"));
  const target = join(directory, "receipt-python.json");
  const script = String.raw`
import json, sys
from datetime import datetime, timezone
from tiba_verifier import create_mandate, create_receipt, generate_ed25519_keypair, sign_mandate, sign_receipt
author = generate_ed25519_keypair()
agent = generate_ed25519_keypair()
mandate = sign_mandate(create_mandate(
  issuer=author["did"], subject=agent["did"], issued_at="2026-09-01T00:00:00.000Z", expires_at="2030-09-20T00:00:00.000Z",
  scope={"actions":[{"protocol":"mcp","action":"tools/call","resource":"notes.local","tool":"notes.write"}],"counterparties":["notes.local"],"data":{"read":[],"write":["notes"]}},
  delegation={"max_depth":0}, revocation={"url":"https://example.invalid/revocations","list_id":"interop","authority":author["did"]}, escalation={"mode":"notify"}
), author["private_key"])
receipt = sign_receipt(create_receipt(
  mandate_chain=[mandate], action={"protocol":"mcp","action":"tools/call","resource":"notes.local","tool":"notes.write","counterparty":"notes.local","data_access":{"read":[],"write":["notes"]}},
  result="success", actor=agent["did"], input={"note":"interoperable"}, output={"ok":True}
), agent["private_key"])
open(sys.argv[1], "w", encoding="utf-8").write(json.dumps(receipt))
`;
  python(["-c", script, target]);
  const receipt = JSON.parse(await readFile(target, "utf8"));
  assert.equal(verifyReceipt(receipt).ok, true);
});
