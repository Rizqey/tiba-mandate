import assert from "node:assert/strict";
import test from "node:test";
import { conservativeOfflineDraft } from "../src/offline.mjs";
import { assertPolicyDraft } from "../src/model.mjs";

test("demo policy draft is narrow and binds the supplied payment counterparty", () => {
  const draft = conservativeOfflineDraft("demo", { demo: true, counterparty: "DemoPayee111111111111111111111111111111111" });
  assert.deepEqual(draft.scope.actions, [
    { protocol: "mcp", action: "tools/call", resource: "notes.local", tool: "notes.write" },
    { protocol: "payment", action: "transfer", resource: "solana:devnet", tool: "transfer_checked" }
  ]);
  assert.deepEqual(draft.scope.counterparties, ["notes.local", "DemoPayee111111111111111111111111111111111"]);
  assert.deepEqual(draft.budget, { amount: "0.001", currency: "USDC", per_action_max: "0.001" });
  assert.equal(assertPolicyDraft(draft), draft);
});

test("model draft validation rejects missing policy fields before confirmation", () => {
  assert.throws(() => assertPolicyDraft({ scope: {}, explanation: "incomplete" }), /nothing was signed/);
});

test("offline parser refuses to invent a payment budget", () => {
  const draft = conservativeOfflineDraft("write a local note");
  assert.equal(draft.budget, null);
  assert.equal(draft.scope.actions.some((action) => action.protocol === "payment"), false);
});
