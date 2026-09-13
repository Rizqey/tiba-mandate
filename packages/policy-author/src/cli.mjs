#!/usr/bin/env node
import { access, mkdir, readFile, writeFile } from "node:fs/promises";
import { constants } from "node:fs";
import { dirname, resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { createInterface } from "node:readline/promises";
import { stdin as input, stdout as output } from "node:process";
import {
  createMandate,
  generateEd25519KeyPair,
  keyPairFromPrivatePem,
  signMandate,
  verifyMandate
} from "@tiba/verifier";
import { conservativeOfflineDraft } from "./offline.mjs";
import { assertPolicyDraft, draftWithOpenAI, draftWithOpenRouter, loadEnvFile } from "./model.mjs";

function args(argv) {
  const values = {};
  for (let index = 0; index < argv.length; index += 1) {
    const token = argv[index];
    if (!token.startsWith("--")) continue;
    const name = token.slice(2);
    const next = argv[index + 1];
    values[name] = !next || next.startsWith("--") ? true : (index += 1, next);
  }
  return values;
}

async function exists(path) {
  try { await access(path, constants.F_OK); return true; } catch { return false; }
}

async function loadOrCreateKey(path) {
  if (await exists(path)) {
    const stored = JSON.parse(await readFile(path, "utf8"));
    if (stored.type !== "tiba.ed25519.private.v0.1" || typeof stored.private_key_pem !== "string") throw new Error("Policy-author key file is not a Tiba Ed25519 key file.");
    return keyPairFromPrivatePem(stored.private_key_pem);
  }
  const pair = generateEd25519KeyPair();
  await mkdir(dirname(path), { recursive: true });
  await writeFile(path, JSON.stringify({ type: "tiba.ed25519.private.v0.1", did: pair.did, private_key_pem: pair.private_key_pem }, null, 2), { encoding: "utf8", mode: 0o600 });
  return pair;
}

function usage() {
  return `Usage:
  node packages/policy-author/src/cli.mjs \\
    --instruction "my agent may ..." \\
    --subject did:key:... \\
    --issuer-key-file demo/.runtime/policy-author.key.json \\
    --expires-at 2026-09-20T00:00:00.000Z \\
    --out mandate.json [--provider openai|openrouter|offline|auto] [--env-file path]
    [--offline-demo --counterparty exact-id] [--allow-offline-fallback]

The CLI always prints a draft and requires SIGN on stdin before it writes a signed mandate.
Use --offline-demo only for the deterministic local demo profile.`;
}

async function modelDraft(options, instruction) {
  const env = options["env-file"] ? await loadEnvFile(resolve(String(options["env-file"]))) : process.env;
  const provider = String(options.provider ?? "auto");
  const fallbackOptions = { demo: options["offline-demo"] === true, counterparty: typeof options.counterparty === "string" ? options.counterparty : undefined };
  if (provider === "offline") return conservativeOfflineDraft(instruction, fallbackOptions);
  if ((provider === "openai" || provider === "auto") && env.OPENAI_API_KEY) {
    try { return await draftWithOpenAI({ instruction, apiKey: env.OPENAI_API_KEY, model: String(options.model ?? env.OPENAI_MODEL ?? "gpt-4.1-mini") }); }
    catch (error) { if (provider === "openai" || !options["allow-offline-fallback"]) throw error; }
  }
  if ((provider === "openrouter" || provider === "auto") && (env.OPENROUTER_API_KEY_AITKL || env.OPENROUTER_API_KEY)) {
    try { return await draftWithOpenRouter({ instruction, apiKey: env.OPENROUTER_API_KEY_AITKL ?? env.OPENROUTER_API_KEY, model: String(options.model ?? env.OPENROUTER_MODEL ?? "openai/gpt-4.1-mini") }); }
    catch (error) { if (provider === "openrouter" || !options["allow-offline-fallback"]) throw error; }
  }
  if (options["allow-offline-fallback"]) return conservativeOfflineDraft(instruction, fallbackOptions);
  throw new Error("No usable policy-author model provider. Set OPENAI_API_KEY or OPENROUTER_API_KEY, or explicitly choose --provider offline.");
}

async function confirm() {
  const terminal = createInterface({ input, output });
  const reply = await terminal.question("Type SIGN to authorize this exact mandate: ");
  terminal.close();
  if (reply.trim() !== "SIGN") throw new Error("Mandate was not signed: confirmation was not SIGN.");
}

export async function run(argv = process.argv.slice(2)) {
  const options = args(argv);
  if (options.help || !options.instruction || !options.subject || !options["issuer-key-file"] || !options["expires-at"] || !options.out) throw new Error(usage());
  const instruction = String(options.instruction);
  const author = await loadOrCreateKey(resolve(String(options["issuer-key-file"])));
  const draft = assertPolicyDraft(await modelDraft(options, instruction));
  const revocation = {
    url: String(options["revocation-url"] ?? draft.revocation?.url ?? "https://tiba.invalid/revocations/default"),
    list_id: String(options["revocation-list-id"] ?? draft.revocation?.list_id ?? "default"),
    authority: author.did
  };
  const unsigned = createMandate({
    issuer: author.did,
    subject: String(options.subject),
    issued_at: String(options["issued-at"] ?? new Date().toISOString()),
    expires_at: String(options["expires-at"]),
    scope: draft.scope,
    ...(draft.budget ? { budget: draft.budget } : {}),
    delegation: draft.delegation,
    revocation,
    escalation: draft.escalation
  });
  const pending = {
    ...unsigned,
    signature: { alg: "Ed25519", kid: author.did, value: "<pending human confirmation>" }
  };
  output.write(`\nGenerated mandate draft (provider: ${options.provider ?? "auto"}):\n${JSON.stringify(pending, null, 2)}\n\n${draft.explanation ? `Draft rationale: ${draft.explanation}\n\n` : ""}`);
  await confirm();
  const signed = signMandate(unsigned, author.privateKey);
  const check = verifyMandate(signed);
  if (!check.ok) throw new Error(`${check.code}: ${check.message}`);
  await mkdir(dirname(resolve(String(options.out))), { recursive: true });
  await writeFile(resolve(String(options.out)), `${JSON.stringify(signed, null, 2)}\n`, "utf8");
  output.write(`Signed mandate written to ${resolve(String(options.out))}\nIssuer: ${author.did}\n`);
  return signed;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  run().catch((error) => { console.error(error instanceof Error ? error.message : error); process.exitCode = 1; });
}
