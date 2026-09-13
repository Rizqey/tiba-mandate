import {
  SOLANA_DEVNET_NETWORK,
  isLikelySolanaTransactionSignature,
  solanaDevnetExplorerUrl,
} from "./constants.mjs";

/**
 * Converts the official x402 SettleResponse into the evidence shape accepted by
 * the Tiba Receipt schema. It rejects anything that is not a Solana-devnet
 * transaction signature rather than inventing a reference.
 */
export function settlementToTibaEvidence(settlement) {
  if (!settlement || settlement.success !== true) {
    throw new Error("x402 settlement was not successful");
  }
  if (settlement.network !== SOLANA_DEVNET_NETWORK) {
    throw new Error("x402 settlement is not on Solana devnet");
  }
  if (!isLikelySolanaTransactionSignature(settlement.transaction)) {
    throw new Error("x402 settlement did not return a usable Solana transaction signature");
  }

  return {
    type: "solana_transaction",
    network: "solana-devnet",
    reference: settlement.transaction,
    url: solanaDevnetExplorerUrl(settlement.transaction),
  };
}

export function settledProof(settlement) {
  const evidence = settlementToTibaEvidence(settlement);
  return {
    protocol: "x402",
    x402_network: SOLANA_DEVNET_NETWORK,
    payment_status: "settled",
    transaction_signature: evidence.reference,
    receipt_evidence: evidence,
  };
}
