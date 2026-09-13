# Tiba Mandate - status

## Milestone 5 of 5: v0 delivered and verified

What works:

- `SPEC.md` and `schema/` define the open v0.1 Mandate, Receipt, delegation,
  revocation, canonical JSON, Ed25519/did:key, privacy, and AP2/x402/TAP/MCP/A2A
  boundaries.
- TypeScript and Python verifiers independently create, sign, and verify the
  same objects. Bidirectional interoperability is tested.
- The MCP guard allowed a local note write, blocked an out-of-scope deletion
  before forwarding it, and returned signed receipts in MCP result metadata.
- The main demo sent 0.001 USDC on Solana devnet and saved the receipt with
  public transaction `2J7uwULaMZtYwQFsY2aKLjpwCXd2rZZixBjpUczJ9QHrU6PbvRzwpkkUqt6PwzhfZ5sPMuzdHw4EUPWTy7cFbLfv`.
  The official devnet RPC later confirmed it succeeded.
- A signed revocation list then caused the fourth action to be denied with
  `TIBA_REVOKED`. A separate Python process, given only the public agent DID
  and the receipt files, verified all four main-demo receipts.
- The optional x402 loopback proof also settled 0.001 USDC on Solana devnet and
  saved a separately verified Tiba receipt under `demo/receipts/x402-run-*`.

How to run:

```powershell
npm run test:js
npm run test:py
npm run test:interop

$env:TIBA_DEMO_CONFIRM_DEVNET = 'YES'
npm run demo
```

Verification evidence:

- 38 automated tests passed across both verifiers, MCP, direct Solana payment,
  policy author, x402, and cross-language interoperability.
- [demo/RUN.md](demo/RUN.md) is the main public transcript.
- The independent verification output and all public receipt artifacts are in
  [demo/receipts](demo/receipts).

Remaining limits:

- `did:key` verifies control of a key, not legal/merchant identity.
- Fresh revocation and global spend safety need a live signed status source and
  shared atomic ledger in a production deployment.
- Only devnet was used. No key or mainnet configuration is committed.
