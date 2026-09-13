import { base58 } from "@scure/base";
import { pathToFileURL } from "node:url";
import { createKeyPairSignerFromBytes } from "@solana/kit";
import { x402Client, x402HTTPClient, wrapFetchWithPayment } from "@x402/fetch";
import { ExactSvmScheme } from "@x402/svm/exact/client";
import {
  MAX_AMOUNT_PER_PAYMENT,
  SOLANA_DEVNET_NETWORK,
  localEndpoint,
  requireLoopbackEndpoint,
  requireRuntimeEnv,
} from "./constants.mjs";
import { settledProof } from "./evidence.mjs";

export async function executeX402Devnet({ privateKey, endpoint: suppliedEndpoint = localEndpoint(), confirmation = "" }) {
  // This prevents an unattended caller from creating even a devnet payment.
  if (confirmation !== "devnet") {
    throw new Error("Set TIBA_X402_CONFIRM=devnet before creating a devnet x402 payment");
  }

  const endpoint = requireLoopbackEndpoint(suppliedEndpoint);
  if (!privateKey) throw new Error("TIBA_X402_SVM_PRIVATE_KEY is required at runtime");
  let signer;
  try {
    signer = await createKeyPairSignerFromBytes(base58.decode(privateKey));
  } catch {
    throw new Error("TIBA_X402_SIGNER_INVALID");
  }

  const client = new x402Client();
  client.setSpendControls({ maxAmountPerPayment: MAX_AMOUNT_PER_PAYMENT });
  // Exact network registration is intentional: this client will not pay an
  // arbitrary `solana:*` challenge.
  client.register(SOLANA_DEVNET_NETWORK, new ExactSvmScheme(signer));

  const httpClient = new x402HTTPClient(client);
  const fetchWithPayment = wrapFetchWithPayment(fetch, client);
  let result;
  try {
    // A local endpoint must not redirect this proof into a different request.
    const response = await fetchWithPayment(endpoint, { method: "GET", redirect: "error" });
    result = await httpClient.processResponse(response);
  } catch {
    throw new Error("TIBA_X402_PAYMENT_REQUEST_FAILED");
  }

  if (result.paymentStatus !== "settled" || !result.header || !("success" in result.header)) {
    throw new Error(`x402 payment did not settle (status: ${result.paymentStatus})`);
  }

  try {
    // Only public settlement output is printed. The private key never leaves this process.
    return settledProof(result.header);
  } catch {
    throw new Error("TIBA_X402_SETTLEMENT_EVIDENCE_INVALID");
  }
}

async function main() {
  const proof = await executeX402Devnet({
    privateKey: requireRuntimeEnv("TIBA_X402_SVM_PRIVATE_KEY"),
    endpoint: process.env.TIBA_X402_ENDPOINT ?? localEndpoint(),
    confirmation: process.env.TIBA_X402_CONFIRM
  });
  // Only public settlement output is printed. The private key never leaves this process.
  console.log(JSON.stringify(proof, null, 2));
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().catch(error => {
    // Only our fixed error codes reach stdout/stderr; signer or provider errors
    // must never accidentally expose runtime key material.
    const message = error instanceof Error && error.message.startsWith("TIBA_X402_")
      ? error.message
      : "TIBA_X402_PROOF_FAILED";
    console.error(message);
    process.exitCode = 1;
  });
}
