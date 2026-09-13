# Tiba Mandate — status

## Milestone 2 of 5: v0.1 specification and schemas

What works:

- `SPEC.md` defines the v0.1 Mandate, Receipt, signed delegation chain,
  revocation model, JCS + Ed25519/did:key verification, error handling, and
  privacy boundaries.
- `schema/` contains JSON Schema 2020-12 documents for mandates, receipts,
  and signed revocation lists.
- Receipts carry a complete signed mandate chain, so an offline verifier can
  validate authorization without a Tiba service.

How to run:

- Read [SPEC.md](SPEC.md) or validate the JSON schema files with any
  Draft 2020-12 compatible JSON Schema validator.

Safety:

- Devnet only. No key is stored in this repository.
