import { authorizeAction, createReceipt, signReceipt } from "@tiba/verifier";
import { executeX402Devnet } from "./client.mjs";
import { requireLoopbackEndpoint } from "./constants.mjs";

export function x402Action({ endpoint, amount = "0.001" }) {
  const url = requireLoopbackEndpoint(endpoint);
  return {
    protocol: "x402",
    action: "http-get",
    resource: "x402:local",
    tool: "exact",
    counterparty: `x402:${url.host}`,
    data_access: { read: [], write: [] },
    amount,
    currency: "USDC"
  };
}

/** Authorize an x402 payment, settle it, and issue its Tiba receipt. */
export async function executeMandatedX402Payment({
  mandateChain,
  agentPrivateKey,
  svmPrivateKey,
  endpoint,
  revocationList,
  requireRevocation = true,
  priorReceipts = [],
  confirmation,
  pay = executeX402Devnet
}) {
  const action = x402Action({ endpoint });
  const leaf = mandateChain.at(-1);
  const input = { endpoint, payment_scheme: "exact", network: "solana-devnet" };
  const authorization = authorizeAction({ mandate_chain: mandateChain, action, revocation_list: revocationList, require_revocation: requireRevocation, prior_receipts: priorReceipts });
  if (!authorization.ok) {
    const receipt = signReceipt(createReceipt({
      mandate_chain: mandateChain, action, result: "denied", reason: authorization.code, actor: leaf.subject,
      input, output: { denied: true, code: authorization.code }
    }), agentPrivateKey);
    return { ok: false, error: authorization, receipt };
  }
  try {
    const proof = await pay({ privateKey: svmPrivateKey, endpoint, confirmation });
    const receipt = signReceipt(createReceipt({
      mandate_chain: mandateChain,
      action,
      result: "success",
      actor: leaf.subject,
      input,
      output: proof,
      evidence: [proof.receipt_evidence]
    }), agentPrivateKey);
    return { ok: true, proof, receipt };
  } catch (error) {
    const output = { code: "TIBA_X402_EXECUTION_FAILED", error: error instanceof Error ? error.message : "x402 payment failed" };
    const receipt = signReceipt(createReceipt({ mandate_chain: mandateChain, action, result: "failure", actor: leaf.subject, input, output }), agentPrivateKey);
    return { ok: false, error, receipt };
  }
}
