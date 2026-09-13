# Tiba Mandate

Tiba is a signed permission slip and a signed receipt for every thing an AI
agent does. A policy author says who may do what, for whom, with which data,
until when, and up to what budget. The agent then signs a portable receipt for
every allowed, failed, or blocked action. A merchant, tool provider, or auditor
can check the receipt themselves with an open verifier; they do not need to
trust Tiba or call a Tiba service.

This repository is the working v0.1 reference implementation. It is devnet
only and never uses mainnet or real funds.

## Quick start

Prerequisites: Node 22+ and Python 3.10+. The Python verifier uses the already
lightweight `cryptography` package; the JavaScript verifier uses Node's built-in
Ed25519 implementation.

```powershell
npm install
npm test
```

Run the complete local story. The script deliberately stops for a human review:
read the unsigned mandate that it prints, then type `SIGN`. It also requires an
explicit devnet broadcast confirmation. It uses the existing devnet-only wallet
configuration at `C:\Users\diony\dev\tiba\.env` by default; override only with
`TIBA_PAYMENT_ENV_FILE` if you have another devnet wallet file.

```powershell
$env:TIBA_DEMO_CONFIRM_DEVNET = 'YES'
npm run demo
```

The demo:

1. uses the policy-author CLI to issue a signed mandate after `SIGN`;
2. allows a scoped MCP local note write and signs a receipt;
3. blocks an out-of-scope MCP call before it reaches the server;
4. sends 0.001 USDC on Solana devnet under the mandate;
5. revokes the mandate and refuses a fourth action; and
6. starts a separate Python process that receives only the agent public
   `did:key` and receipt files, then verifies every receipt.

Public artifacts from the verified run are in
[demo/receipts](demo/receipts), with the readable transcript in
[demo/RUN.md](demo/RUN.md). The direct-payment receipt includes a public
Solana devnet transaction reference and explorer link.

To independently verify a receipt directory yourself:

```powershell
$env:PYTHONPATH = (Resolve-Path packages/verifier-py).Path
python -m tiba_verifier.cli `
  --receipts-dir demo/receipts/run-2026-09-13T12-06-58-433Z `
  --trusted-actor (Get-Content -Raw demo/receipts/run-2026-09-13T12-06-58-433Z/agent-public.did).Trim()
```

The optional x402 harness proves a real 0.001-USDC x402 settlement against a
loopback seller using the free Solana-devnet facilitator, then wraps it in a
Tiba receipt. It has its own narrow ephemeral test mandate and requires a
separate explicit confirmation:

```powershell
$env:TIBA_X402_CONFIRM = 'devnet'
npm --workspace @tiba/x402-proof run demo
```

## What is in the standard

- [SPEC.md](SPEC.md) is the v0.1 normative specification.
- [schema](schema) contains JSON Schema 2020-12 documents for Mandates,
  Receipts, and signed revocation lists.
- [packages/verifier-ts](packages/verifier-ts) and
  [packages/verifier-py](packages/verifier-py) create, sign, and independently
  verify objects. Both enforce expiry, revocation, scope, budget, delegation
  narrowing, input/output hashes, and Ed25519 `did:key` signatures.
- [packages/mcp-guard](packages/mcp-guard) is a transport-neutral MCP
  middleware plus a minimal stdio client/server demo. It derives action facts
  from trusted tool configuration, blocks before forwarding, serializes local
  budget checks, writes receipts, and returns the receipt in MCP
  `result._meta["org.tiba/receipt"]`.
- [packages/solana-payment](packages/solana-payment) adapts the existing Tiba
  Solana devnet settlement rail. It hard-pins Circle devnet USDC and checks the
  official devnet genesis hash before it loads a payer key or signs a transfer.
- [packages/policy-author](packages/policy-author) turns plain English into a
  conservative draft through OpenAI Responses API or OpenRouter, displays it,
  and requires literal `SIGN` before signing. It has an explicit deterministic
  offline profile for reproducible demos only.
- [packages/x402-proof](packages/x402-proof) is the optional loopback-only
  Solana-devnet x402 proof and mandate-receipt wrapper.

## How Tiba fits with AP2, x402, TAP, MCP, and A2A

Tiba is an envelope and evidence layer, not a replacement for those systems.

| System | It already does | Tiba adds |
| --- | --- | --- |
| [Google AP2](https://github.com/google-agentic-commerce/AP2) | Payment checkout mandates, payment credentials, receipts, and disputes. | Cross-protocol delegation plus non-payment tool-action receipts. Tiba references AP2 IDs/hashes; it does not copy checkout credentials or JWTs. |
| [x402](https://www.x402.org/) | HTTP 402 payment requirements, payment payloads, facilitator verification, and settlement. | Policy checks before payment, aggregate spend accounting, and a receipt for the whole agent action. x402 remains the payment protocol. |
| [Visa Trusted Agent Protocol](https://developer.visa.com/capabilities/trusted-agent-protocol) | Visa-network trust signals for agentic commerce. | A network-neutral evidence format for any tool/action. TAP HTTP signatures and network rules remain TAP's job. |
| [MCP](https://modelcontextprotocol.io/) | Agent-to-tool protocol and server-defined tool semantics. | A mandate guard around `tools/call` and a receipt in MCP result metadata; Tiba does not replace tool schemas or server authorization. |
| [A2A](https://a2a-protocol.org/latest/) | Agent discovery, tasks, messages, and extension negotiation. | A portable mandate-chain/receipt extension and strict sub-delegation; Tiba does not replace Agent Cards or task state. |

## Limits

- A `did:key` proves control of a key, not a person's legal identity or a
  merchant's legitimacy.
- A receipt proves what the signing agent claims and what policy it had. Verify
  external settlement evidence through Solana, x402, AP2, TAP, or the relevant
  system before relying on it.
- Revocation is strongest with a fresh signed status list. Offline signature
  verification can prove a historical record but cannot prove today's status.
- A process-local ledger prevents races only inside that process. Production
  deployments need an atomic shared spend/reservation ledger.
- Tiba never makes an unsafe server safe on its own. The guard must be placed
  on the real execution path, and the underlying tool or payment provider still
  needs its own authorization and validation.
- Hashes are not encryption. Sensitive values need salt and protected private
  evidence storage outside a receipt.

See [DECISIONS.md](DECISIONS.md) for the v0 choices and [STATUS.md](STATUS.md)
for the current verified state.
