# Decisions

## Tiba v0.1 - 2026-09-13

- **Wire format:** the signed objects use `type: "tiba.mandate"`,
  `"tiba.receipt"`, or `"tiba.revocation_list"` plus `version: "0.1"`.
  Signing removes the `signature` field, JCS-canonicalizes the rest, and uses
  Ed25519. Money is a fixed decimal string, never a JSON number.
- **Identity and independence:** issuer, subject, actor, and revocation
  authority are Ed25519 `did:key` identifiers. A full signed mandate chain is
  embedded in every receipt, so verification has no Tiba service dependency.
- **Time representation:** v0.1 accepts only calendar-valid
  `YYYY-MM-DDTHH:mm:ss.sssZ` timestamps. The narrow form prevents JavaScript
  and Python from signing or interpreting invalid dates differently.
- **Scope and payments:** policies are deny-by-default allow-lists. Direct
  USDC transfers use the protocol-neutral tuple `payment` / `transfer` /
  `solana:devnet` / `transfer_checked`; x402 uses `x402` / `http-get` /
  `x402:local` / `exact`. Counterparty and data selectors must match exactly.
- **Privacy:** receipts commit only SHA-256 hashes of inputs and outputs. They
  contain public mandate data and public evidence references, never raw tool
  payloads, private keys, bearer tokens, or wallet seeds.
- **Execution safety:** MCP and payment enforcers require a signed revocation
  list by default. Direct settlement forces the Circle devnet USDC mint and
  checks the official Solana devnet genesis hash before loading a payer key or
  signing a transaction. The direct payment demo deliberately ignores custom
  RPC/mint values from the existing wallet environment.
- **Budget concurrency:** `McpGuard` serializes its calls. Direct payments have
  a process-local `MandatedPaymentLedger` that holds the authorization lock
  through settlement. Cross-process production deployments need a shared,
  atomic ledger/reservation store; v0 does not pretend a local array solves
  that problem globally.
- **Existing Tiba reuse:** the checked-out `C:\Users\diony\dev\tiba` project
  exposes the requested Solana devnet rail in local branch `solana-rail`,
  `src/lib/rails/solana.ts`. This repository adapts its devnet guard, Circle
  mint, TransferChecked transaction, memo, confirmation, and explorer URL
  behavior instead of reimplementing settlement from scratch.
- **Policy author model path:** the CLI supports OpenAI Responses API and
  OpenRouter structured output, always showing the unsigned draft and waiting
  for literal `SIGN`. A live OpenAI attempt was rejected by the configured
  environment and the available OpenRouter provider returned an error; no key
  value was logged. The committed end-to-end demo therefore uses the explicit
  deterministic offline demo profile, not a silent model fallback.
- **x402:** the official free facilitator supports Solana devnet. The optional
  local proof is loopback-only, hard-pins Solana devnet, caps each payment at
  0.001 USDC, requires `TIBA_X402_CONFIRM=devnet`, and wraps a settled x402
  call in a Tiba receipt. A real devnet proof was completed and independently
  verified; its public artifact is under `demo/receipts/x402-run-*`.
