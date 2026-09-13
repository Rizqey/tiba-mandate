# Tiba Mandate - status

## Milestone 3 of 5: independent verifier libraries

What works:

- TypeScript and Python both create, sign, and independently verify Tiba v0.1
  Mandates, Receipts, and signed revocation lists using JCS-compatible JSON,
  Ed25519, and `did:key`.
- Both reject tampering, expiry, over-budget actions, revoked mandates, widened
  sub-mandates, malformed timestamps, unknown nested schema fields, and a
  successful Solana payment without canonical transaction evidence.
- A bidirectional interoperability test proves Python verifies a TypeScript
  receipt and TypeScript verifies a Python receipt.

How to run:

```powershell
npm --workspace @tiba/verifier test
npm run test:py
npm run test:interop
```

Safety:

- No key is stored in the verifier fixtures or output.
- Signature-only offline verification is intentionally separate from fresh
  revocation and complete-spend-ledger verification.
