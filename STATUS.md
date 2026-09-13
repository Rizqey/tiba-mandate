# Tiba Mandate - status

## Milestone 4 of 5: execution integrations

What works:

- `McpGuard` intercepts MCP tool calls, derives facts from trusted tool policy,
  requires signed revocation status, blocks denied calls before forwarding, and
  returns a signed receipt in `result._meta["org.tiba/receipt"]`.
- Direct Solana settlement reuses the existing Tiba devnet rail. It only accepts
  Circle devnet USDC, checks the full official devnet genesis hash before it
  loads a payer key, and signs a payment receipt with a public explorer link.
- The payment and MCP guards serialize local budget use. This is deliberately
  not presented as a cross-process ledger.
- The policy-author CLI has OpenAI and OpenRouter structured-output paths plus
  a deterministic offline demo profile. It always waits for literal `SIGN`
  before signing.
- The optional x402 loopback proof is hard-pinned to Solana devnet, caps spend
  at 0.001 USDC, requires explicit confirmation, and wraps settlement in a
  Tiba receipt.

How to run:

```powershell
npm --workspace @tiba/mcp-guard test
npm --workspace @tiba/solana-payment test
npm --workspace @tiba/policy-author test
npm --workspace @tiba/x402-proof test
```

Safety:

- All execution integrations fail closed without a signed revocation list.
- Devnet-only guards run before a payer key is loaded or a transaction is
  signed. No private key is committed.
