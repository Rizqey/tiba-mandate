import { authorizeAction, createReceipt, signReceipt } from "@tiba/verifier";
import { sendUsdcDevnet } from "./settlement.mjs";

/**
 * Process-local serial ledger for a mandate execution session. It holds the
 * authorization lock through settlement, so concurrent calls cannot both pass
 * the same remaining-budget check. Multi-process deployments must replace it
 * with a shared atomic ledger/reservation service.
 */
export class MandatedPaymentLedger {
  constructor(priorReceipts = []) {
    this.priorReceipts = [...priorReceipts];
    this.tail = Promise.resolve();
  }

  async exclusive(work) {
    const previous = this.tail;
    let release;
    this.tail = new Promise((resolve) => { release = resolve; });
    await previous;
    try { return await work(this.priorReceipts); }
    finally { release(); }
  }

  commit(receipt) {
    if (receipt.result === "success") this.priorReceipts.push(receipt);
  }
}

export function microsToUsdc(amountMicros) {
  if (typeof amountMicros !== "bigint" || amountMicros <= 0n) throw new Error("amountMicros must be a positive bigint");
  const value = amountMicros.toString().padStart(7, "0");
  const whole = value.slice(0, -6);
  const fraction = value.slice(-6).replace(/0+$/, "");
  return fraction ? `${whole}.${fraction}` : whole;
}

export function paymentAction({ recipientAddress, amountMicros }) {
  return {
    protocol: "payment",
    action: "transfer",
    resource: "solana:devnet",
    tool: "transfer_checked",
    counterparty: recipientAddress,
    data_access: { read: [], write: [] },
    amount: microsToUsdc(amountMicros),
    currency: "USDC"
  };
}

/** Authorize, execute devnet transfer, and sign the corresponding receipt. */
async function executeOne({
  mandateChain,
  agentPrivateKey,
  recipientAddress,
  amountMicros,
  revocationList,
  requireRevocation = true,
  priorReceipts = [],
  env = process.env,
  intentId,
  settle = sendUsdcDevnet
}) {
  const action = paymentAction({ recipientAddress, amountMicros });
  const leaf = mandateChain.at(-1);
  const input = { recipient_address: recipientAddress, amount_micros: amountMicros.toString(), intent_id: intentId };
  const authorized = authorizeAction({ mandate_chain: mandateChain, action, revocation_list: revocationList, require_revocation: requireRevocation, prior_receipts: priorReceipts });
  if (!authorized.ok) {
    const receipt = signReceipt(createReceipt({
      mandate_chain: mandateChain, action, result: "denied", reason: authorized.code, actor: leaf.subject,
      input, output: { denied: true, code: authorized.code }
    }), agentPrivateKey);
    return { ok: false, error: authorized, receipt };
  }

  try {
    const settlement = await settle([{ recipientAddress, amountMicros, intentId }], env);
    const receipt = signReceipt(createReceipt({
      mandate_chain: mandateChain,
      action,
      result: "success",
      actor: leaf.subject,
      input,
      output: settlement,
      evidence: [{
        type: "solana_transaction",
        network: "solana-devnet",
        reference: settlement.transaction_signature,
        url: settlement.explorer_url
      }]
    }), agentPrivateKey);
    return { ok: true, settlement, receipt };
  } catch (error) {
    const output = { code: error?.code ?? "SOLANA_EXECUTION_FAILED", error: error instanceof Error ? error.message : "Solana payment failed" };
    const receipt = signReceipt(createReceipt({ mandate_chain: mandateChain, action, result: "failure", actor: leaf.subject, input, output }), agentPrivateKey);
    return { ok: false, error, receipt };
  }
}

export async function executeMandatedUsdcPayment(options) {
  const { ledger } = options;
  if (ledger === undefined) return executeOne(options);
  if (!(ledger instanceof MandatedPaymentLedger)) throw new TypeError("ledger must be a MandatedPaymentLedger");
  return ledger.exclusive(async (priorReceipts) => {
    const result = await executeOne({ ...options, priorReceipts });
    if (result.ok) ledger.commit(result.receipt);
    return result;
  });
}
