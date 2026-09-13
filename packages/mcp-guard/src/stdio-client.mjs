import { spawn } from "node:child_process";
import { createInterface } from "node:readline";

/** Minimal JSONL stdio MCP client for the local demo; no SDK dependency. */
export class StdioMcpClient {
  constructor(command, args = [], options = {}) {
    this.command = command;
    this.args = args;
    this.options = options;
    this.nextId = 1;
    this.pending = new Map();
  }

  async start() {
    this.child = spawn(this.command, this.args, { stdio: ["pipe", "pipe", "pipe"], ...this.options });
    this.child.on("error", (error) => this.rejectAll(error));
    this.child.on("exit", (code) => this.rejectAll(new Error(`MCP server exited (${code})`)));
    createInterface({ input: this.child.stdout, crlfDelay: Infinity }).on("line", (line) => {
      try {
        const message = JSON.parse(line);
        const pending = this.pending.get(message.id);
        if (!pending) return;
        this.pending.delete(message.id);
        if (message.error) pending.reject(Object.assign(new Error(message.error.message), { code: message.error.code }));
        else pending.resolve(message.result);
      } catch { /* Ignore a malformed server line; a pending request will time out/exit. */ }
    });
    await this.request("initialize", { protocolVersion: "2025-03-26", capabilities: {}, clientInfo: { name: "tiba-guard", version: "0.1" } });
  }

  request(method, params = {}) {
    if (!this.child?.stdin.writable) return Promise.reject(new Error("MCP server is not running"));
    const id = this.nextId++;
    return new Promise((resolve, reject) => {
      this.pending.set(id, { resolve, reject });
      this.child.stdin.write(`${JSON.stringify({ jsonrpc: "2.0", id, method, params })}\n`);
    });
  }

  callTool(name, args) {
    return this.request("tools/call", { name, arguments: args });
  }

  rejectAll(error) {
    for (const pending of this.pending.values()) pending.reject(error);
    this.pending.clear();
  }

  async stop() {
    if (!this.child) return;
    this.child.kill();
  }
}
