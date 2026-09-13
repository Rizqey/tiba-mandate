import copy
from datetime import datetime, timezone
import unittest

from tiba_verifier import (
    authorize_action,
    create_mandate,
    create_receipt,
    generate_ed25519_keypair,
    hash_object,
    sign_mandate,
    sign_receipt,
    sign_revocation_list,
    verify_mandate,
    verify_mandate_chain,
    verify_revocation_list,
    verify_receipt,
)


AUTHOR = generate_ed25519_keypair()
AGENT = generate_ed25519_keypair()
NOW = datetime(2026, 9, 13, tzinfo=timezone.utc)
NOW_UTC = "2026-09-13T00:00:00.000Z"
FUTURE = "2030-09-20T00:00:00.000Z"
WRITE_ACTION = {
    "protocol": "mcp", "action": "tools/call", "resource": "notes.local", "tool": "notes.write",
    "counterparty": "notes.local", "data_access": {"read": [], "write": ["demo/notes"]},
}
PAYMENT_ACTION = {
    "protocol": "payment", "action": "transfer", "resource": "solana:devnet", "tool": "transfer_checked",
    "counterparty": "vendor-a", "data_access": {"read": [], "write": []}, "amount": "0.50", "currency": "USDC",
}
SOLANA_SIGNATURE = "3" * 88
SOLANA_EVIDENCE = {
    "type": "solana_transaction",
    "network": "solana-devnet",
    "reference": SOLANA_SIGNATURE,
    "url": f"https://explorer.solana.com/tx/{SOLANA_SIGNATURE}?cluster=devnet",
}


def root(**overrides):
    content = {
        "issuer": AUTHOR["did"], "subject": AGENT["did"], "issued_at": "2026-09-12T00:00:00.000Z", "expires_at": FUTURE,
        "scope": {
            "actions": [
                {"protocol": "mcp", "action": "tools/call", "resource": "notes.local", "tool": "notes.write"},
                {"protocol": "payment", "action": "transfer", "resource": "solana:devnet", "tool": "transfer_checked"},
            ],
            "counterparties": ["notes.local", "vendor-a"], "data": {"read": [], "write": ["demo/notes"]},
        },
        "budget": {"amount": "2.00", "currency": "USDC", "per_action_max": "1.00"},
        "delegation": {"max_depth": 2},
        "revocation": {"url": "https://example.invalid/revocations", "list_id": "main", "authority": AUTHOR["did"]},
        "escalation": {"mode": "notify"},
    }
    content.update(overrides)
    return sign_mandate(create_mandate(**content), AUTHOR["private_key"])


class VerifierTests(unittest.TestCase):
    def payment_mandate(self):
        return root(scope={
            "actions": [{"protocol": "payment", "action": "transfer", "resource": "solana:devnet", "tool": "transfer_checked"}],
            "counterparties": ["vendor-a"],
            "data": {"read": [], "write": []},
        })

    def signed_payment_receipt(self):
        mandate = self.payment_mandate()
        receipt = sign_receipt(create_receipt(
            mandate_chain=[mandate], action=PAYMENT_ACTION, result="success", actor=AGENT["did"],
            executed_at=NOW_UTC, input={"amount": "0.50"}, output={"settled": True}, evidence=[SOLANA_EVIDENCE],
        ), AGENT["private_key"])
        return mandate, receipt

    def test_signed_mandate_and_receipt(self):
        mandate = root()
        self.assertTrue(verify_mandate(mandate).ok)
        receipt = sign_receipt(create_receipt(mandate_chain=[mandate], action=WRITE_ACTION, result="success", actor=AGENT["did"], input={"path": "a.txt"}, output={"ok": True}), AGENT["private_key"])
        self.assertTrue(verify_receipt(receipt).ok)

    def test_tampered_receipt(self):
        mandate = root()
        receipt = sign_receipt(create_receipt(mandate_chain=[mandate], action=WRITE_ACTION, result="success", actor=AGENT["did"], input={}, output={}), AGENT["private_key"])
        receipt["result"] = "failure"
        self.assertFalse(verify_receipt(receipt).ok)

    def test_expired_mandate(self):
        mandate = root(expires_at="2026-09-12T23:59:59.000Z")
        result = authorize_action(mandate_chain=[mandate], action=WRITE_ACTION, at=NOW)
        self.assertFalse(result.ok)
        self.assertEqual(result.code, "TIBA_EXPIRED")

    def test_over_budget(self):
        mandate = root()
        payment = {**PAYMENT_ACTION, "amount": "1.01"}
        result = authorize_action(mandate_chain=[mandate], action=payment, at=NOW)
        self.assertFalse(result.ok)
        self.assertEqual(result.code, "TIBA_BUDGET_EXCEEDED")
        prior = sign_receipt(create_receipt(mandate_chain=[mandate], action={**payment, "amount": "1.00"}, result="success", actor=AGENT["did"], input={}, output={}, evidence=[SOLANA_EVIDENCE]), AGENT["private_key"])
        result = authorize_action(mandate_chain=[mandate], action={**payment, "amount": "1.00"}, at=NOW, prior_receipts=[prior])
        self.assertTrue(result.ok)
        result = authorize_action(mandate_chain=[mandate], action={**payment, "amount": "1.01"}, at=NOW, prior_receipts=[prior])
        self.assertFalse(result.ok)

    def test_revoked(self):
        mandate = root()
        revocations = sign_revocation_list({"type": "tiba.revocation_list", "version": "0.1", "id": "revocations:1", "issuer": AUTHOR["did"], "list_id": "main", "issued_at": NOW_UTC, "next_update": FUTURE, "revoked": [{"mandate_id": mandate["id"], "revoked_at": NOW_UTC}]}, AUTHOR["private_key"])
        result = authorize_action(mandate_chain=[mandate], action=WRITE_ACTION, at=NOW, revocation_list=revocations, require_revocation=True)
        self.assertFalse(result.ok)
        self.assertEqual(result.code, "TIBA_REVOKED")

    def test_widened_sub_mandate(self):
        parent = root()
        child = sign_mandate(create_mandate(
            issuer=AGENT["did"], subject=generate_ed25519_keypair()["did"], issued_at="2026-09-13T00:00:00.000Z", expires_at=FUTURE,
            scope={"actions": [{"protocol": "mcp", "action": "tools/call", "resource": "notes.local", "tool": "notes.delete"}], "counterparties": ["notes.local"], "data": {"read": [], "write": ["demo/notes"]}},
            delegation={"max_depth": 1, "parent": {"id": parent["id"], "hash": hash_object(parent)}},
            revocation=parent["revocation"], escalation=parent["escalation"],
        ), AGENT["private_key"])
        result = verify_mandate_chain([parent, child])
        self.assertFalse(result.ok)
        self.assertEqual(result.code, "TIBA_DELEGATION_WIDENED")

    def test_rejects_noncanonical_or_impossible_timestamps(self):
        for timestamp in ("2026-09-12T00:00:00Z", "2026-02-30T00:00:00.000Z", "2026-09-12T00:00:00.000+00:00"):
            with self.subTest(timestamp=timestamp):
                mandate = root()
                mandate["issued_at"] = timestamp
                result = verify_mandate(mandate)
                self.assertFalse(result.ok)
                self.assertEqual(result.code, "TIBA_SCHEMA_INVALID")

        result = authorize_action(mandate_chain=[root()], action=WRITE_ACTION, at="2026-09-13T00:00:00Z")
        self.assertFalse(result.ok)
        self.assertEqual(result.code, "TIBA_SCHEMA_INVALID")

    def test_rejects_unknown_nested_schema_fields(self):
        def parent_with_extra(_: dict):
            return {"max_depth": 2, "parent": {"id": "parent:1", "hash": "sha256-" + "A" * 43, "extra": True}}

        mutations = {
            "scope": lambda mandate: mandate["scope"].update({"extra": True}),
            "scope action": lambda mandate: mandate["scope"]["actions"][0].update({"extra": True}),
            "scope data": lambda mandate: mandate["scope"]["data"].update({"extra": True}),
            "budget": lambda mandate: mandate["budget"].update({"extra": True}),
            "delegation": lambda mandate: mandate["delegation"].update({"extra": True}),
            "delegation parent": lambda mandate: mandate.update({"delegation": parent_with_extra(mandate)}),
            "revocation": lambda mandate: mandate["revocation"].update({"extra": True}),
            "escalation": lambda mandate: mandate["escalation"].update({"extra": True}),
            "signature": lambda mandate: mandate["signature"].update({"extra": True}),
        }
        for label, mutate in mutations.items():
            with self.subTest(label=label):
                mandate = root()
                mutate(mandate)
                result = verify_mandate(mandate)
                self.assertFalse(result.ok)
                self.assertEqual(result.code, "TIBA_SCHEMA_INVALID")

        mandate = root()
        revocations = sign_revocation_list({
            "type": "tiba.revocation_list", "version": "0.1", "id": "revocations:strict", "issuer": AUTHOR["did"],
            "list_id": "main", "issued_at": NOW_UTC, "next_update": FUTURE,
            "revoked": [{"mandate_id": mandate["id"], "revoked_at": NOW_UTC}],
        }, AUTHOR["private_key"])
        revocations["revoked"][0]["extra"] = True
        result = verify_revocation_list(revocations, mandate, NOW)
        self.assertFalse(result.ok)
        self.assertEqual(result.code, "TIBA_REVOCATION_INVALID")

        receipt = sign_receipt(create_receipt(
            mandate_chain=[mandate], action=WRITE_ACTION, result="success", actor=AGENT["did"],
            executed_at=NOW_UTC, input={}, output={}, evidence=[{"type": "mcp_call", "reference": "request:1"}],
        ), AGENT["private_key"])
        receipt["evidence"][0]["extra"] = True
        result = verify_receipt(receipt)
        self.assertFalse(result.ok)
        self.assertEqual(result.code, "TIBA_SCHEMA_INVALID")

    def test_successful_solana_payment_requires_canonical_evidence(self):
        _, receipt = self.signed_payment_receipt()
        self.assertTrue(verify_receipt(receipt).ok)

        missing = copy.deepcopy(receipt)
        del missing["evidence"]
        result = verify_receipt(missing)
        self.assertFalse(result.ok)
        self.assertEqual(result.code, "TIBA_SCHEMA_INVALID")

        wrong_network = copy.deepcopy(receipt)
        wrong_network["evidence"][0]["network"] = "solana-mainnet"
        result = verify_receipt(wrong_network)
        self.assertFalse(result.ok)
        self.assertEqual(result.code, "TIBA_SCHEMA_INVALID")

        wrong_url = copy.deepcopy(receipt)
        wrong_url["evidence"][0]["url"] = f"https://explorer.solana.com/tx/{SOLANA_SIGNATURE}?cluster=mainnet-beta"
        result = verify_receipt(wrong_url)
        self.assertFalse(result.ok)
        self.assertEqual(result.code, "TIBA_SCHEMA_INVALID")


if __name__ == "__main__":
    unittest.main()
