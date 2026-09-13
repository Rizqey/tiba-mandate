import { readFile } from "node:fs/promises";

const POLICY_DRAFT_SCHEMA = {
  type: "object",
  additionalProperties: false,
  required: ["scope", "delegation", "revocation", "escalation", "explanation"],
  properties: {
    scope: {
      type: "object",
      additionalProperties: false,
      required: ["actions", "counterparties", "data"],
      properties: {
        actions: {
          type: "array",
          minItems: 1,
          items: {
            type: "object",
            additionalProperties: false,
            required: ["protocol", "action", "resource", "tool"],
            properties: {
              protocol: { type: "string" },
              action: { type: "string" },
              resource: { type: "string" },
              tool: { type: "string" }
            }
          }
        },
        counterparties: { type: "array", items: { type: "string" } },
        data: {
          type: "object",
          additionalProperties: false,
          required: ["read", "write"],
          properties: {
            read: { type: "array", items: { type: "string" } },
            write: { type: "array", items: { type: "string" } }
          }
        }
      }
    },
    budget: {
      type: ["object", "null"],
      additionalProperties: false,
      required: ["amount", "currency"],
      properties: {
        amount: { type: "string", pattern: "^[0-9]+(\\.[0-9]+)?$" },
        currency: { type: "string" },
        per_action_max: { type: "string", pattern: "^[0-9]+(\\.[0-9]+)?$" }
      }
    },
    delegation: {
      type: "object",
      additionalProperties: false,
      required: ["max_depth"],
      properties: { max_depth: { type: "integer", minimum: 0, maximum: 8 } }
    },
    revocation: {
      type: "object",
      additionalProperties: false,
      required: ["url", "list_id"],
      properties: { url: { type: "string" }, list_id: { type: "string" } }
    },
    escalation: {
      type: "object",
      additionalProperties: false,
      required: ["mode"],
      properties: {
        mode: { enum: ["deny", "require_confirmation", "notify"] },
        url: { type: "string" }
      }
    },
    explanation: { type: "string" }
  }
};

const SYSTEM_PROMPT = `You convert a human's limited agent instruction into a conservative Tiba Mandate draft. Return JSON only. Tiba is deny-by-default: do not invent broad permissions, wildcard selectors, vendors, data access, a budget, or a duration. For tool access use protocol \"mcp\", action \"tools/call\", an exact resource, and exact tool name where the instruction identifies them. For a devnet USDC payment use protocol \"payment\", action \"transfer\", resource \"solana:devnet\", tool \"transfer_checked\". Counterparties must be exact identifiers stated by the human. If a field is absent, use an empty array or a deny escalation; do not guess. The caller fills in identities and expiry. Give a short explanation of the choices.`;

function trimQuoted(value) {
  const text = value.trim();
  if ((text.startsWith('"') && text.endsWith('"')) || (text.startsWith("'") && text.endsWith("'"))) return text.slice(1, -1);
  return text;
}

/** Parse only simple KEY=VALUE dotenv lines; never writes or logs a secret. */
export async function loadEnvFile(path) {
  const result = {};
  const text = await readFile(path, "utf8");
  for (const line of text.split(/\r?\n/)) {
    const match = line.match(/^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*?)\s*$/);
    if (match && !match[1].startsWith("#")) result[match[1]] = trimQuoted(match[2]);
  }
  return result;
}

function responseText(body) {
  if (typeof body.output_text === "string") return body.output_text;
  for (const item of body.output ?? []) {
    for (const content of item.content ?? []) {
      if (typeof content.text === "string") return content.text;
    }
  }
  throw new Error("Policy author model returned no text output.");
}

async function jsonResponse(response) {
  const body = await response.json().catch(() => ({}));
  if (!response.ok) {
    // Providers sometimes echo a malformed credential in their diagnostic.
    // Do not surface provider text through the CLI or logs.
    void body;
    throw new Error(`Policy author model request failed (HTTP ${response.status}).`);
  }
  return body;
}

function object(value) {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}

function hasOnly(value, keys) {
  return object(value) && Object.keys(value).every((key) => keys.includes(key));
}

function exactString(value) {
  return typeof value === "string" && value.length > 0 && !value.includes("*") && !/\s/.test(value);
}

function stringArray(value) {
  return Array.isArray(value) && value.every(exactString) && new Set(value).size === value.length;
}

function decimal(value) {
  return typeof value === "string" && /^(0|[1-9][0-9]*)(\.[0-9]{1,18})?$/.test(value);
}

/** Reject malformed or unexpectedly broad model output before human review. */
export function assertPolicyDraft(value) {
  if (!hasOnly(value, ["scope", "budget", "delegation", "revocation", "escalation", "explanation"]) || !object(value.scope) || !hasOnly(value.scope, ["actions", "counterparties", "data"]) || !Array.isArray(value.scope.actions) || value.scope.actions.length === 0 || !stringArray(value.scope.counterparties) || !object(value.scope.data) || !hasOnly(value.scope.data, ["read", "write"]) || !stringArray(value.scope.data.read) || !stringArray(value.scope.data.write) || !object(value.delegation) || !hasOnly(value.delegation, ["max_depth"]) || !Number.isInteger(value.delegation.max_depth) || value.delegation.max_depth < 0 || value.delegation.max_depth > 8 || !object(value.revocation) || !hasOnly(value.revocation, ["url", "list_id"]) || typeof value.revocation.url !== "string" || !exactString(value.revocation.list_id) || !object(value.escalation) || !hasOnly(value.escalation, ["mode", "url"]) || !["deny", "require_confirmation", "notify"].includes(value.escalation.mode) || (value.escalation.url !== undefined && typeof value.escalation.url !== "string") || typeof value.explanation !== "string") {
    throw new Error("Policy author model returned an invalid mandate draft; nothing was signed.");
  }
  for (const action of value.scope.actions) {
    if (!hasOnly(action, ["protocol", "action", "resource", "tool"]) || ![action.protocol, action.action, action.resource, action.tool].every(exactString)) {
      throw new Error("Policy author model returned an invalid action selector; nothing was signed.");
    }
  }
  if (value.budget !== null && value.budget !== undefined && (!object(value.budget) || !hasOnly(value.budget, ["amount", "currency", "per_action_max"]) || !decimal(value.budget.amount) || !/^[A-Z][A-Z0-9._-]{1,15}$/.test(value.budget.currency) || (value.budget.per_action_max !== undefined && !decimal(value.budget.per_action_max)))) {
    throw new Error("Policy author model returned an invalid budget; nothing was signed.");
  }
  return value;
}

export async function draftWithOpenAI({ instruction, apiKey, model = "gpt-4.1-mini" }) {
  if (!apiKey) throw new Error("OPENAI_API_KEY is required for the OpenAI policy-author provider.");
  const response = await fetch("https://api.openai.com/v1/responses", {
    method: "POST",
    headers: { "content-type": "application/json", authorization: `Bearer ${apiKey}` },
    body: JSON.stringify({
      model,
      input: [
        { role: "system", content: [{ type: "input_text", text: SYSTEM_PROMPT }] },
        { role: "user", content: [{ type: "input_text", text: instruction }] }
      ],
      text: { format: { type: "json_schema", name: "tiba_mandate_draft", strict: true, schema: POLICY_DRAFT_SCHEMA } }
    })
  });
  return assertPolicyDraft(JSON.parse(responseText(await jsonResponse(response))));
}

export async function draftWithOpenRouter({ instruction, apiKey, model = "openai/gpt-4.1-mini" }) {
  if (!apiKey) throw new Error("OPENROUTER_API_KEY is required for the OpenRouter policy-author provider.");
  const response = await fetch("https://openrouter.ai/api/v1/chat/completions", {
    method: "POST",
    headers: { "content-type": "application/json", authorization: `Bearer ${apiKey}` },
    body: JSON.stringify({
      model,
      response_format: {
        type: "json_schema",
        json_schema: { name: "tiba_mandate_draft", strict: true, schema: POLICY_DRAFT_SCHEMA }
      },
      messages: [{ role: "system", content: SYSTEM_PROMPT }, { role: "user", content: instruction }]
    })
  });
  const body = await jsonResponse(response);
  return assertPolicyDraft(JSON.parse(body.choices?.[0]?.message?.content ?? ""));
}

export const policyDraftSchema = POLICY_DRAFT_SCHEMA;
