# Tiba x402 devnet proof

This is a small local x402 seller and buyer built with the official x402 v2
packages. It is deliberately hard-wired to Solana devnet and the free
`https://x402.org/facilitator`; it cannot be pointed at mainnet by an environment
variable. The server exposes one paid local endpoint, and the client converts the
official `PAYMENT-RESPONSE` settlement `transaction` into a Tiba-ready
`solana_transaction` evidence object, then the mandated wrapper signs it as a
normal Tiba receipt.

It is a devnet-only proof integration. A live payment requires a separately
funded **devnet** USDC wallet and the explicit runtime confirmation below. No
key is logged or committed.

## Install

From the repository root, install workspace dependencies once:

```powershell
npm install
```

## Run the local seller

Set only a public Solana devnet receiving address, then start the server:

```powershell
$env:TIBA_X402_PAY_TO = "<public-devnet-receiving-address>"
npm run server --workspace @tiba/x402-proof
```

The endpoint is bound to `127.0.0.1:4021`. An unpaid check is safe and should
return HTTP 402 with a `PAYMENT-REQUIRED` header:

```powershell
curl.exe -i http://127.0.0.1:4021/paid
```

`/health` is free and reports the fixed CAIP-2 Solana-devnet network identifier.

## Run the paid buyer

Only after a separate Tiba mandate check has authorized the spend, supply the
base58 64-byte **devnet** signer at runtime and make the opt-in explicit:

```powershell
$env:TIBA_X402_SVM_PRIVATE_KEY = "<runtime-only-devnet-key>"
$env:TIBA_X402_CONFIRM = "devnet"
npm run client --workspace @tiba/x402-proof
```

The client only calls a loopback endpoint and only registers the exact Solana
devnet network. It caps one payment at `$0.001`. On a settled response it prints
only public data in this shape:

```json
{
  "protocol": "x402",
  "x402_network": "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1",
  "payment_status": "settled",
  "transaction_signature": "<Solana transaction signature>",
  "receipt_evidence": {
    "type": "solana_transaction",
    "network": "solana-devnet",
    "reference": "<Solana transaction signature>",
    "url": "https://explorer.solana.com/tx/<Solana transaction signature>?cluster=devnet"
  }
}
```

`src/mandated-payment.mjs` performs that outer mandate check and signs the
receipt. The client refuses a non-devnet network or a settlement response
without a plausible Solana transaction signature instead of fabricating
evidence.

## One-command mandated proof

The harness starts the loopback seller, derives a runtime-only SVM signer from
the existing devnet wallet file, issues a deliberately narrow ephemeral testing
mandate, settles the payment, and saves a Tiba receipt. It never prints the
wallet key. It must be explicitly confirmed:

```powershell
$env:TIBA_X402_CONFIRM = "devnet"
npm run demo --workspace @tiba/x402-proof
```

It reads `C:\Users\diony\dev\tiba\.env` by default; set
`TIBA_PAYMENT_ENV_FILE` to a different **devnet-only** wallet file if needed.
The core `demo/run.mjs` remains the human-confirmed policy-author story.

## What is proven now

The automated tests prove the safe evidence conversion, mandate wrapper, and
devnet/local-only guards. The endpoint can also be exercised through its unpaid
402 route without any wallet. A real 0.001-USDC devnet settlement was completed
and independently verified; its public receipt is in
[`demo/receipts/x402-run-2026-09-13T12-14-26-966Z`](../../demo/receipts/x402-run-2026-09-13T12-14-26-966Z).

The implementation follows the official [x402 seller quickstart](https://docs.x402.org/getting-started/quickstart-for-sellers),
[buyer quickstart](https://docs.x402.org/getting-started/quickstart-for-buyers),
and [network/facilitator support](https://docs.x402.org/core-concepts/network-and-token-support).
