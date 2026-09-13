/** A conservative deterministic draft path for tests and offline demos only. */
function quoted(text) {
  return [...text.matchAll(/["'`]([^"'`]+)["'`]/g)].map((match) => match[1].trim()).filter(Boolean);
}

function amountAndCurrency(text) {
  const match = text.match(/(?:up\s+to|spend|pay|send)\s+(\d+(?:\.\d+)?)\s+(USDC|USD|EURC)\b/i);
  return match ? { amount: match[1], currency: match[2].toUpperCase() } : null;
}

/**
 * It intentionally produces a narrow profile. It does not infer vendors or
 * data paths that the instruction did not make explicit.
 */
export function conservativeOfflineDraft(instruction, { demo = false, counterparty } = {}) {
  if (demo) {
    return {
      scope: {
        actions: [
          { protocol: "mcp", action: "tools/call", resource: "notes.local", tool: "notes.write" },
          { protocol: "payment", action: "transfer", resource: "solana:devnet", tool: "transfer_checked" }
        ],
        counterparties: ["notes.local", counterparty ?? "tiba-demo-payee"],
        data: { read: [], write: ["demo/notes"] }
      },
      budget: { amount: "0.001", currency: "USDC", per_action_max: "0.001" },
      delegation: { max_depth: 0 },
      revocation: { url: "https://tiba.invalid/revocations/demo", list_id: "demo" },
      escalation: { mode: "notify" },
      explanation: "Offline demo profile: one local notes write and one 0.001 USDC Solana-devnet transfer."
    };
  }

  const lower = instruction.toLowerCase();
  const actions = [];
  const writes = [];
  if (/\b(note|mcp|write)\b/.test(lower)) {
    actions.push({ protocol: "mcp", action: "tools/call", resource: "notes.local", tool: "notes.write" });
    writes.push("notes");
  }
  const budget = amountAndCurrency(instruction);
  if (budget) actions.push({ protocol: "payment", action: "transfer", resource: "solana:devnet", tool: "transfer_checked" });
  if (actions.length === 0) actions.push({ protocol: "local", action: "none", resource: "none", tool: "none" });

  const names = quoted(instruction).filter((item) => !/agent|usdc|week|note/i.test(item));
  return {
    scope: {
      actions,
      counterparties: names.length ? names : [budget ? "UNSPECIFIED_COUNTERPARTY" : "local"],
      data: { read: [], write: writes }
    },
    budget: budget ? { ...budget, per_action_max: budget.amount } : null,
    delegation: { max_depth: 0 },
    revocation: { url: "https://tiba.invalid/revocations/offline", list_id: "offline" },
    escalation: { mode: "notify" },
    explanation: "Conservative offline draft; review and edit any UNSPECIFIED selector before signing."
  };
}
