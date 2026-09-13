/**
 * Adapted from C:\Users\diony\dev\tiba's local `solana-rail` branch,
 * commit 7fbe7d597545199127132ca528c344d47b9f9509.  The flow is preserved:
 * devnet gate, Circle devnet USDC, a TransferChecked instruction, an audit
 * memo, confirmation, and a public devnet explorer URL.
 */
import { Connection, Keypair, PublicKey, Transaction, TransactionInstruction } from "@solana/web3.js";
import {
  createAssociatedTokenAccountIdempotentInstruction,
  createTransferCheckedInstruction,
  getAssociatedTokenAddressSync
} from "@solana/spl-token";

export const SOLANA_USDC_DEVNET_MINT = "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU";
export const SOLANA_USDC_DECIMALS = 6;
export const SOLANA_DEVNET_RPC = "https://api.devnet.solana.com";
// A devnet RPC's immutable genesis hash. Check it before any key is loaded,
// signed transaction is built, or transaction is broadcast.
export const SOLANA_DEVNET_GENESIS_HASH = "EtWTRABZaYq6iMfeYKouRu166VU2xqa1wcaWoxPkrZBG";
export const MAX_BATCH_SIZE = 8;
const MEMO_PROGRAM_ID = new PublicKey("MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr");

export class SolanaPaymentError extends Error {
  constructor(code, message, options) {
    super(message, options);
    this.name = "SolanaPaymentError";
    this.code = code;
  }
}

function value(env, name) {
  const item = env[name]?.trim();
  return item || undefined;
}

export function requireDevnet(env = process.env) {
  const declared = [value(env, "SOLANA_NETWORK"), value(env, "SOLANA_CLUSTER")].filter(Boolean);
  if (declared.length === 0 || declared.some((network) => network !== "devnet")) {
    throw new SolanaPaymentError("SOLANA_NETWORK_NOT_DEVNET", "Solana settlement is devnet-only. Set SOLANA_NETWORK=devnet.");
  }
}

export function solanaUsdcMint(env = process.env) {
  const configured = value(env, "SOLANA_USDC_MINT");
  if (configured && configured !== SOLANA_USDC_DEVNET_MINT) {
    throw new SolanaPaymentError("SOLANA_MINT_NOT_DEVNET", "Solana settlement only permits the Circle devnet USDC mint.");
  }
  return new PublicKey(SOLANA_USDC_DEVNET_MINT);
}

export function solanaConnection(env = process.env) {
  return new Connection(value(env, "SOLANA_RPC_URL") ?? SOLANA_DEVNET_RPC, "confirmed");
}

export function solanaExplorerTxUrl(signature) {
  return `https://explorer.solana.com/tx/${signature}?cluster=devnet`;
}

export function assertDevnetGenesisHash(genesisHash) {
  if (genesisHash !== SOLANA_DEVNET_GENESIS_HASH) {
    throw new SolanaPaymentError("SOLANA_NETWORK_NOT_DEVNET", "Configured Solana RPC is not Solana devnet.");
  }
}

export async function assertDevnetConnection(connection) {
  assertDevnetGenesisHash(await connection.getGenesisHash());
}

export function keypairFromEnv(env = process.env) {
  requireDevnet(env);
  const encoded = value(env, "SOLANA_PRIVATE_KEY");
  if (!encoded) {
    throw new SolanaPaymentError("SOLANA_PRIVATE_KEY_MISSING", "SOLANA_PRIVATE_KEY is required for Solana settlement.");
  }
  let pair;
  try {
    pair = Keypair.fromSecretKey(Uint8Array.from(JSON.parse(encoded)));
  } catch (cause) {
    throw new SolanaPaymentError("SOLANA_PRIVATE_KEY_INVALID", "SOLANA_PRIVATE_KEY must be a Solana CLI JSON byte array.", { cause });
  }
  const configured = value(env, "SOLANA_ADDRESS");
  if (configured && configured !== pair.publicKey.toBase58()) {
    throw new SolanaPaymentError("SOLANA_ADDRESS_MISMATCH", "SOLANA_ADDRESS does not match SOLANA_PRIVATE_KEY.");
  }
  return pair;
}

function recipientKey(request) {
  if (typeof request.amountMicros !== "bigint" || request.amountMicros <= 0n) {
    throw new SolanaPaymentError("INVALID_PAYOUT", "Payout amount must be a positive integer number of USDC micros.");
  }
  try {
    return new PublicKey(String(request.recipientAddress).trim());
  } catch (cause) {
    throw new SolanaPaymentError("INVALID_PAYOUT", `Invalid Solana recipient address for intent ${request.intentId}.`, { cause });
  }
}

export function buildSolanaPayoutTransaction(requests, payer, mint = solanaUsdcMint()) {
  if (!Array.isArray(requests) || requests.length === 0) {
    throw new SolanaPaymentError("INVALID_PAYOUT", "Batch payout requires at least one payout.");
  }
  if (requests.length > MAX_BATCH_SIZE) {
    throw new SolanaPaymentError("INVALID_PAYOUT", `Batch payout is limited to ${MAX_BATCH_SIZE} payouts per transaction.`);
  }
  const recipients = requests.map(recipientKey);
  const tx = new Transaction();
  tx.add(new TransactionInstruction({
    keys: [{ pubkey: payer, isSigner: true, isWritable: false }],
    programId: MEMO_PROGRAM_ID,
    data: Buffer.from(requests.map((request) => `Tiba payout ${request.intentId}`).join("; "), "utf8")
  }));
  const payerAta = getAssociatedTokenAddressSync(mint, payer, true);
  requests.forEach((request, index) => {
    const recipientAta = getAssociatedTokenAddressSync(mint, recipients[index], true);
    tx.add(createAssociatedTokenAccountIdempotentInstruction(payer, recipientAta, recipients[index], mint));
    tx.add(createTransferCheckedInstruction(payerAta, mint, recipientAta, payer, request.amountMicros, SOLANA_USDC_DECIMALS));
  });
  return tx;
}

export async function sendUsdcDevnet(requests, env = process.env) {
  requireDevnet(env);
  const connection = solanaConnection(env);
  // A label alone must never route a transaction to mainnet. Check genesis
  // before touching the payer key or creating a signed transaction.
  await assertDevnetConnection(connection);
  const payer = keypairFromEnv(env);
  const tx = buildSolanaPayoutTransaction(requests, payer.publicKey, solanaUsdcMint(env));
  let recent;
  try {
    recent = await connection.getLatestBlockhash("confirmed");
    tx.recentBlockhash = recent.blockhash;
    tx.lastValidBlockHeight = recent.lastValidBlockHeight;
    tx.feePayer = payer.publicKey;
    tx.sign(payer);
    const signature = await connection.sendRawTransaction(tx.serialize());
    const confirmation = await connection.confirmTransaction({ signature, ...recent }, "confirmed");
    if (confirmation.value.err) {
      throw new Error(JSON.stringify(confirmation.value.err));
    }
    return {
      transaction_signature: signature,
      explorer_url: solanaExplorerTxUrl(signature),
      network: "solana-devnet",
      mint: solanaUsdcMint(env).toBase58(),
      payer: payer.publicKey.toBase58()
    };
  } catch (cause) {
    if (cause instanceof SolanaPaymentError) throw cause;
    throw new SolanaPaymentError("SOLANA_EXECUTION_FAILED", "Solana devnet USDC transaction could not be confirmed.", { cause });
  }
}
