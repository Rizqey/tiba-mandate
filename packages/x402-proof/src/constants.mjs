export const SOLANA_DEVNET_NETWORK = "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1";
export const SOLANA_DEVNET_RPC = "https://api.devnet.solana.com";
export const FACILITATOR_URL = "https://x402.org/facilitator";
export const LOCAL_HOST = "127.0.0.1";
export const DEFAULT_PORT = 4021;
export const PAID_PATH = "/paid";
export const PRICE = "$0.001";
export const MAX_AMOUNT_PER_PAYMENT = "$0.001";

export function requireRuntimeEnv(name) {
  const value = process.env[name];
  if (!value) {
    throw new Error(`${name} is required at runtime`);
  }
  return value;
}

export function requireLoopbackEndpoint(value) {
  const endpoint = new URL(value);
  const localHosts = new Set(["127.0.0.1", "localhost", "[::1]"]);
  if (!localHosts.has(endpoint.hostname)) {
    throw new Error("TIBA_X402_ENDPOINT must be a local loopback URL");
  }
  if (endpoint.protocol !== "http:" && endpoint.protocol !== "https:") {
    throw new Error("TIBA_X402_ENDPOINT must use HTTP(S)");
  }
  return endpoint;
}

export function localEndpoint(port = DEFAULT_PORT) {
  return `http://${LOCAL_HOST}:${port}${PAID_PATH}`;
}

export function solanaDevnetExplorerUrl(transactionSignature) {
  return `https://explorer.solana.com/tx/${encodeURIComponent(transactionSignature)}?cluster=devnet`;
}

export function isLikelySolanaTransactionSignature(value) {
  return typeof value === "string" && /^[1-9A-HJ-NP-Za-km-z]{64,100}$/.test(value);
}
