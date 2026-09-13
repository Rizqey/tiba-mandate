import { mkdir, writeFile } from "node:fs/promises";
import { resolve } from "node:path";
import {
  authorizeAction,
  createReceipt,
  signReceipt
} from "@tiba/verifier";

const RECEIPT_META_KEY = "org.tiba/receipt";
const AUDIT_PERSISTENCE_CODE = "TIBA_AUDIT_PERSISTENCE_FAILED";

function isRecord(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function auditPersistenceError() {
  // Do not reflect filesystem paths or operating-system error details through
  // an MCP response. The code makes this failure actionable for the caller.
  return {
    code: AUDIT_PERSISTENCE_CODE,
    message: "The signed Tiba receipt was returned but could not be persisted."
  };
}

function toolErrorResult(error, receipt) {
  return injectReceipt({
    isError: true,
    content: [{ type: "text", text: error.message }]
  }, receipt);
}

/**
 * A `tools/call` result is an object in MCP. Preserve an upstream result's
 * fields and metadata, while making the guard's signed receipt available to a
 * normal MCP client. The fallback is deliberate for non-conforming adapters:
 * callers still receive a valid MCP result rather than losing the receipt.
 */
function injectReceipt(result, receipt) {
  const base = isRecord(result)
    ? result
    : { isError: false, content: [{ type: "text", text: JSON.stringify(result) }] };
  const meta = isRecord(base._meta) ? base._meta : {};
  return {
    ...base,
    _meta: { ...meta, [RECEIPT_META_KEY]: receipt }
  };
}

/**
 * Transport-neutral MCP middleware. Give it any MCP client's `callTool`
 * function and it signs a Receipt before returning the tool result.
 */
export class McpGuard {
  constructor({ mandateChain, agentPrivateKey, revocationList, requireRevocation = true, receiptDir, serverId, toolPolicy, callTool }) {
    this.mandateChain = mandateChain;
    this.agentPrivateKey = agentPrivateKey;
    this.revocationList = revocationList;
    this.requireRevocation = requireRevocation;
    this.receiptDir = resolve(receiptDir);
    this.serverId = serverId;
    this.toolPolicy = toolPolicy;
    this.callTool = callTool;
    this.priorReceipts = [];
    // Start this as soon as the guard is created. It is deliberately not a
    // gate for a permitted action: an audit disk outage must not turn a real,
    // successful upstream tool result into a synthetic tool failure.
    this.receiptDirectoryPreflight = mkdir(this.receiptDir, { recursive: true })
      .then(() => undefined)
      .catch((error) => error);
    // Every authorization and subsequent prior-receipt update is one critical
    // section. This prevents two concurrent calls from both spending the same
    // remaining budget in one guard process.
    this.callTail = Promise.resolve();
  }

  actionFor(name) {
    const policy = this.toolPolicy[name];
    if (!policy) {
      // Unknown tool descriptions are never supplied by the agent. This exact
      // value makes the denial auditable while failing scope matching closed.
      return {
        protocol: "mcp", action: "tools/call", resource: this.serverId, tool: name,
        counterparty: this.serverId, data_access: { read: [], write: [] }
      };
    }
    return {
      protocol: "mcp",
      action: "tools/call",
      resource: policy.resource ?? this.serverId,
      tool: name,
      counterparty: policy.counterparty ?? this.serverId,
      data_access: { read: [...(policy.read ?? [])], write: [...(policy.write ?? [])] },
      ...(policy.amount !== undefined ? { amount: policy.amount, currency: policy.currency } : {})
    };
  }

  async persist(receipt) {
    const preflightError = await this.receiptDirectoryPreflight;
    if (preflightError) throw preflightError;
    await mkdir(this.receiptDir, { recursive: true });
    const path = resolve(this.receiptDir, `${receipt.id.replace(/[^A-Za-z0-9._-]/g, "_")}.json`);
    await writeFile(path, `${JSON.stringify(receipt, null, 2)}\n`, "utf8");
    return path;
  }

  async signedReceipt({ action, result, reason, toolInput, toolOutput, evidence }) {
    const leaf = this.mandateChain.at(-1);
    const receipt = signReceipt(createReceipt({
      mandate_chain: this.mandateChain,
      action,
      result,
      ...(reason ? { reason } : {}),
      actor: leaf.subject,
      input: toolInput,
      output: toolOutput,
      ...(evidence ? { evidence } : {})
    }), this.agentPrivateKey);
    let persistenceError;
    try {
      await this.persist(receipt);
    } catch (error) {
      persistenceError = auditPersistenceError(error);
    }
    if (result === "success") this.priorReceipts.push(receipt);
    return { receipt, persistenceError };
  }

  async call(name, args = {}) {
    const call = this.callTail.then(() => this.callOne(name, args));
    // Leave the queue usable if a programming/key error escapes `callOne`.
    this.callTail = call.catch(() => undefined);
    return call;
  }

  async callOne(name, args) {
    const action = this.actionFor(name);
    const authorization = authorizeAction({
      mandate_chain: this.mandateChain,
      action,
      revocation_list: this.revocationList,
      require_revocation: this.requireRevocation,
      prior_receipts: this.priorReceipts
    });
    if (!authorization.ok) {
      const { receipt, persistenceError } = await this.signedReceipt({
        action,
        result: "denied",
        reason: authorization.code,
        toolInput: args,
        toolOutput: { denied: true, code: authorization.code }
      });
      const error = { code: authorization.code, message: authorization.message };
      return {
        isError: true,
        error,
        output: toolErrorResult(error, receipt),
        receipt,
        ...(persistenceError ? { auditPersistenceError: persistenceError } : {})
      };
    }
    try {
      const output = await this.callTool(name, args);
      const { receipt, persistenceError } = await this.signedReceipt({ action, result: "success", toolInput: args, toolOutput: output });
      return {
        isError: false,
        output: injectReceipt(output, receipt),
        receipt,
        ...(persistenceError ? { auditPersistenceError: persistenceError } : {})
      };
    } catch (error) {
      const output = { error: error instanceof Error ? error.message : "MCP tool failed" };
      const { receipt, persistenceError } = await this.signedReceipt({ action, result: "failure", toolInput: args, toolOutput: output });
      return {
        isError: true,
        error: output,
        output: toolErrorResult({ message: output.error }, receipt),
        receipt,
        ...(persistenceError ? { auditPersistenceError: persistenceError } : {})
      };
    }
  }
}
