# Tiba Mandate — status

## Milestone 1 of 5: repository foundation

What works:

- Local Git repository initialized; no remote is configured or used.
- Secret-safe `.gitignore` and `.env.example` are in place.
- The existing Tiba source was audited. Its `solana-rail` local branch contains a reusable devnet USDC settlement module; the currently checked-out branch is Sui-only.

How to run:

- This milestone has no executable artifact yet. The next milestones add the verifier packages, guard, payment adapter, and demo.

Safety:

- Devnet only. No key is stored in this repository.
