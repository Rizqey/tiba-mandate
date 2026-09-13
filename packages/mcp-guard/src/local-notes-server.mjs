/** A deliberately tiny MCP stdio server used by the guard demo. */
import { mkdir, writeFile } from "node:fs/promises";
import { resolve, relative } from "node:path";
import { createInterface } from "node:readline";

const notesRoot = resolve(process.env.TIBA_NOTES_DIR || "./demo/notes");

function safeNotePath(value) {
  const target = resolve(notesRoot, String(value || ""));
  if (!value || relative(notesRoot, target).startsWith("..") || target === notesRoot) {
    throw new Error("Note path must stay inside TIBA_NOTES_DIR.");
  }
  return target;
}

function reply(id, result) {
  process.stdout.write(`${JSON.stringify({ jsonrpc: "2.0", id, result })}\n`);
}

function failure(id, code, message) {
  process.stdout.write(`${JSON.stringify({ jsonrpc: "2.0", id, error: { code, message } })}\n`);
}

async function handle(message) {
  if (message.method === "initialize") {
    return { protocolVersion: "2025-03-26", capabilities: { tools: {} }, serverInfo: { name: "tiba-local-notes", version: "0.1" } };
  }
  if (message.method === "tools/list") {
    return {
      tools: [{
        name: "notes.write",
        description: "Write a named plaintext note under the local notes directory.",
        inputSchema: {
          type: "object",
          additionalProperties: false,
          required: ["path", "text"],
          properties: { path: { type: "string" }, text: { type: "string" } }
        }
      }]
    };
  }
  if (message.method === "tools/call") {
    const { name, arguments: args = {} } = message.params ?? {};
    if (name !== "notes.write") throw new Error(`Unknown tool: ${name}`);
    const target = safeNotePath(args.path);
    await mkdir(notesRoot, { recursive: true });
    await mkdir(resolve(target, ".."), { recursive: true });
    await writeFile(target, String(args.text), "utf8");
    return { content: [{ type: "text", text: `Wrote ${String(args.path)}` }], isError: false };
  }
  throw new Error(`Unsupported MCP method: ${message.method}`);
}

const input = createInterface({ input: process.stdin, crlfDelay: Infinity });
input.on("line", async (line) => {
  let message;
  try {
    message = JSON.parse(line);
    const result = await handle(message);
    if (message.id !== undefined) reply(message.id, result);
  } catch (error) {
    if (message?.id !== undefined) failure(message.id, -32602, error instanceof Error ? error.message : "Invalid request");
  }
});
