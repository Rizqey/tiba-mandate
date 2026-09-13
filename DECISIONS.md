# Decisions

## v0 foundation — 2026-09-13

- **Wire format:** use `kind: "tiba-mandate" | "tiba-receipt"` and `version: "0.1"`; signatures are detached from the canonical payload as a `signature` object. Amounts are integer minor units (`amountMicros` for USDC) so budget checks do not use floating point.
- **Identity:** issuer and signing key identifiers use `did:key` Ed25519 public keys. The protocol is deliberately registries-free for independent verification.
- **Scope:** mandates are allow-lists. A missing permission is denied. Sub-mandates must be strictly equal to or narrower than their parent in every bounded dimension.
- **Sensitive data:** receipts retain SHA-256 hashes of inputs and outputs, not payloads. Demo keys are generated at runtime in ignored state and are never committed.
- **Existing Tiba reuse:** the currently checked-out `C:\Users\diony\dev\tiba` branch only exposes a Sui testnet rail, but its local `solana-rail` branch contains the requested Solana-devnet USDC rail at `src/lib/rails/solana.ts`. Tiba Mandate will reuse/adapt that module's devnet guard, USDC mint, transfer-checked transaction, memo, and explorer receipt behavior rather than inventing another settlement path.
- **x402:** it is not a prerequisite for a protocol-neutral receipt. v0 will document the extension point; a live x402 facilitator is only added if it can be proven in the time and resource budget without replacing the mandatory direct devnet payment.
