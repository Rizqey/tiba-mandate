# Tiba demo transcript

Run: `2026-09-13T12-06-58-433Z`

1. The policy-author CLI rendered a narrow draft and received `SIGN` before writing the mandate.
2. The MCP guard allowed one scoped local note write and signed a receipt.
3. The MCP guard blocked `notes.delete` before forwarding it and signed a denied receipt.
4. The payment guard sent 0.001 USDC on Solana devnet under the mandate. Transaction: [2J7uwULaMZtYwQFsY2aKLjpwCXd2rZZixBjpUczJ9QHrU6PbvRzwpkkUqt6PwzhfZ5sPMuzdHw4EUPWTy7cFbLfv](https://explorer.solana.com/tx/2J7uwULaMZtYwQFsY2aKLjpwCXd2rZZixBjpUczJ9QHrU6PbvRzwpkkUqt6PwzhfZ5sPMuzdHw4EUPWTy7cFbLfv?cluster=devnet).
5. A signed revocation list revoked the mandate; a fourth action was refused with `TIBA_REVOKED`.
6. A separate Python process received only the agent public `did:key` and receipt files, and verified all four receipts.

Artifacts: [receipts/run-2026-09-13T12-06-58-433Z](receipts/run-2026-09-13T12-06-58-433Z)
