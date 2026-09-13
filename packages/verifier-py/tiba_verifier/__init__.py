"""Dependency-light Tiba v0.1 mandate and receipt verifier.

This mirrors the TypeScript implementation without trusting a Tiba service.
Only `cryptography` is used for the Ed25519 primitive; canonicalization, did:key
multicodec handling, exact decimal budget math, and policy checks are local.
"""

from __future__ import annotations

import base64
import copy
import hashlib
import json
import re
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation
from typing import Any, Mapping, Sequence
from urllib.parse import urlsplit

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

__all__ = [
    "TibaError", "Check", "generate_ed25519_keypair", "keypair_from_private_pem",
    "canonicalize", "hash_bytes", "hash_object", "did_from_public_key", "public_key_from_did",
    "sign_object", "verify_object_signature", "create_mandate", "sign_mandate", "verify_mandate",
    "verify_mandate_chain", "sign_revocation_list", "verify_revocation_list", "authorize_action",
    "create_receipt", "sign_receipt", "verify_receipt", "assert_authorized", "assert_verified_receipt",
]

_B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_ED25519_MULTICODEC = b"\xed\x01"
_DECIMAL = re.compile(r"^(0|[1-9][0-9]*)(\.[0-9]{1,18})?$")
_CURRENCY = re.compile(r"^[A-Z][A-Z0-9._-]{1,15}$")
_IDENTIFIER = re.compile(r"^[A-Za-z0-9._:-]{1,200}$")
_HASH = re.compile(r"^sha256-[A-Za-z0-9_-]{43}$")
_REASON = re.compile(r"^TIBA_[A-Z0-9_]+$")
_TIMESTAMP = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$")
_SIGNATURE = re.compile(r"^[A-Za-z0-9_-]{86}$")
_SOLANA_BASE58 = re.compile(r"^[1-9A-HJ-NP-Za-km-z]{1,128}$")
_ESCALATION_RANK = {"notify": 0, "require_confirmation": 1, "deny": 2}


class TibaError(ValueError):
    """A fail-closed Tiba error with the v0.1 machine-readable code."""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


@dataclass(frozen=True)
class Check:
    ok: bool
    code: str | None = None
    message: str | None = None
    leaf: dict[str, Any] | None = None
    root: dict[str, Any] | None = None
    spent: str | None = None


def _ok(**extra: Any) -> Check:
    return Check(True, **extra)


def _fail(code: str, message: str) -> Check:
    return Check(False, code, message)


def _raise(check: Check) -> None:
    if not check.ok:
        raise TibaError(check.code or "TIBA_SCHEMA_INVALID", check.message or "Tiba verification failed")


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _from_b64url(value: str) -> bytes:
    if not re.fullmatch(r"[A-Za-z0-9_-]+", value):
        raise TibaError("TIBA_SCHEMA_INVALID", "Invalid base64url value.")
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def _b58encode(data: bytes) -> str:
    number = int.from_bytes(data, "big")
    result = ""
    while number:
        number, remainder = divmod(number, 58)
        result = _B58[remainder] + result
    leading = len(data) - len(data.lstrip(b"\0"))
    return "1" * leading + (result or ("" if leading else "1"))


def _b58decode(value: str) -> bytes:
    if not value:
        raise TibaError("TIBA_DID_KEY_INVALID", "Empty base58 key.")
    number = 0
    for letter in value:
        try:
            number = number * 58 + _B58.index(letter)
        except ValueError as exc:
            raise TibaError("TIBA_DID_KEY_INVALID", "did:key contains non-base58 characters.") from exc
    encoded = number.to_bytes((number.bit_length() + 7) // 8, "big")
    return b"\0" * (len(value) - len(value.lstrip("1"))) + encoded


def _jcs_string(value: str) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"))


def canonicalize(value: Any) -> str:
    """Canonical JSON for the finite JSON values used by Tiba's v0.1 profile."""
    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, str):
        return _jcs_string(value)
    if isinstance(value, int) and not isinstance(value, bool):
        return str(value)
    if isinstance(value, float):
        if value != value or value in (float("inf"), float("-inf")):
            raise TibaError("TIBA_CANONICALIZATION_FAILED", "Non-finite numbers are not JCS values.")
        # v0 objects use decimal strings for money and do not use floats.
        return json.dumps(value, ensure_ascii=False, separators=(",", ":"))
    if isinstance(value, (list, tuple)):
        return "[" + ",".join(canonicalize(item) for item in value) + "]"
    if isinstance(value, Mapping):
        keys = sorted(value.keys(), key=lambda key: str(key).encode("utf-16be"))
        chunks: list[str] = []
        for key in keys:
            if not isinstance(key, str):
                raise TibaError("TIBA_CANONICALIZATION_FAILED", "JSON object keys must be strings.")
            item = value[key]
            if item is _UNSET:
                raise TibaError("TIBA_CANONICALIZATION_FAILED", "Undefined values are not JSON.")
            chunks.append(_jcs_string(key) + ":" + canonicalize(item))
        return "{" + ",".join(chunks) + "}"
    raise TibaError("TIBA_CANONICALIZATION_FAILED", "Unsupported JCS value.")


_UNSET = object()


def hash_bytes(value: bytes | str) -> str:
    if isinstance(value, str):
        value = value.encode("utf-8")
    return "sha256-" + _b64url(hashlib.sha256(value).digest())


def hash_object(value: Any) -> str:
    return hash_bytes(canonicalize(value))


def did_from_public_key(public_key: Ed25519PublicKey | bytes | str) -> str:
    if isinstance(public_key, str):
        public_key = serialization.load_pem_public_key(public_key.encode("utf-8"))
    if isinstance(public_key, bytes):
        public_key = Ed25519PublicKey.from_public_bytes(public_key)
    if not isinstance(public_key, Ed25519PublicKey):
        raise TibaError("TIBA_DID_KEY_INVALID", "Tiba requires an Ed25519 public key.")
    raw = public_key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return "did:key:z" + _b58encode(_ED25519_MULTICODEC + raw)


def public_key_from_did(did: str) -> Ed25519PublicKey:
    if not isinstance(did, str) or not did.startswith("did:key:z"):
        raise TibaError("TIBA_DID_KEY_INVALID", "Tiba requires a did:key Ed25519 identifier.")
    decoded = _b58decode(did[len("did:key:z"):])
    if len(decoded) != 34 or decoded[:2] != _ED25519_MULTICODEC:
        raise TibaError("TIBA_DID_KEY_INVALID", "did:key is not the Ed25519 multicodec.")
    try:
        return Ed25519PublicKey.from_public_bytes(decoded[2:])
    except ValueError as exc:
        raise TibaError("TIBA_DID_KEY_INVALID", "did:key could not be decoded as Ed25519.") from exc


def generate_ed25519_keypair() -> dict[str, Any]:
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    return {
        "did": did_from_public_key(public_key),
        "private_key": private_key,
        "public_key": public_key,
        "private_key_pem": private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ).decode("utf-8"),
        "public_key_pem": public_key.public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("utf-8"),
    }


def keypair_from_private_pem(value: str) -> dict[str, Any]:
    private_key = serialization.load_pem_private_key(value.encode("utf-8"), password=None)
    if not isinstance(private_key, Ed25519PrivateKey):
        raise TibaError("TIBA_DID_KEY_INVALID", "Private key is not Ed25519.")
    public_key = private_key.public_key()
    return {
        "did": did_from_public_key(public_key),
        "private_key": private_key,
        "public_key": public_key,
        "private_key_pem": value,
        "public_key_pem": public_key.public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("utf-8"),
    }


def _private_key(value: Ed25519PrivateKey | str) -> Ed25519PrivateKey:
    if isinstance(value, str):
        loaded = serialization.load_pem_private_key(value.encode("utf-8"), password=None)
        if not isinstance(loaded, Ed25519PrivateKey):
            raise TibaError("TIBA_DID_KEY_INVALID", "Private key is not Ed25519.")
        return loaded
    return value


def _without_signature(value: Mapping[str, Any]) -> dict[str, Any]:
    return {key: item for key, item in value.items() if key != "signature"}


def sign_object(unsigned: Mapping[str, Any], signer: Ed25519PrivateKey | str, expected_did: str | None = None) -> dict[str, Any]:
    key = _private_key(signer)
    did = did_from_public_key(key.public_key())
    if expected_did and did != expected_did:
        raise TibaError("TIBA_SIGNATURE_INVALID", "Signing key does not match the object identity.")
    output = _without_signature(unsigned)
    output["signature"] = {"alg": "Ed25519", "kid": did, "value": _b64url(key.sign(canonicalize(output).encode("utf-8")))}
    return output


def verify_object_signature(value: Mapping[str, Any], expected_did: str | None = None) -> Check:
    signature = value.get("signature")
    if (
        not isinstance(signature, Mapping)
        or not _only_known(signature, {"alg", "kid", "value"})
        or signature.get("alg") != "Ed25519"
        or not isinstance(signature.get("kid"), str)
        or not isinstance(signature.get("value"), str)
        or not _SIGNATURE.fullmatch(signature["value"])
    ):
        return _fail("TIBA_SCHEMA_INVALID", "Object is missing a valid Ed25519 signature object.")
    if expected_did and signature["kid"] != expected_did:
        return _fail("TIBA_SIGNATURE_INVALID", "Signature kid does not match object identity.")
    try:
        public_key_from_did(signature["kid"]).verify(_from_b64url(signature["value"]), canonicalize(_without_signature(value)).encode("utf-8"))
        return _ok()
    except TibaError as exc:
        return _fail(exc.code, str(exc))
    except InvalidSignature:
        return _fail("TIBA_SIGNATURE_INVALID", "Ed25519 signature verification failed.")
    except Exception:
        return _fail("TIBA_SIGNATURE_INVALID", "Ed25519 signature verification failed.")


def _timestamp(value: Any) -> datetime | None:
    if not isinstance(value, str) or not _TIMESTAMP.fullmatch(value):
        return None
    try:
        # The grammar check above prevents datetime.fromisoformat from accepting
        # alternate-but-equivalent timestamp spellings. Tiba v0.1 signs one UTC
        # representation only: YYYY-MM-DDTHH:mm:ss.sssZ.
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def _selector(value: Any) -> bool:
    return isinstance(value, str) and 1 <= len(value) <= 2048 and " " not in value and (value == "*" or "*" not in value)


def _decimal(value: Any) -> bool:
    return isinstance(value, str) and bool(_DECIMAL.fullmatch(value))


def _known_extensions(value: Any) -> bool:
    return isinstance(value, Mapping) and not value


def _only_known(value: Mapping[str, Any], keys: set[str]) -> bool:
    return set(value).issubset(keys)


def _uri(value: Any, *, max_length: int = 2048) -> bool:
    """Accept an absolute URI without whitespace, as required by JSON Schema URI fields."""
    if not isinstance(value, str) or not 1 <= len(value) <= max_length or any(character.isspace() for character in value):
        return False
    try:
        return bool(urlsplit(value).scheme)
    except ValueError:
        return False


def _validate_evidence(evidence: Any, *, action: Mapping[str, Any], result: str) -> Check:
    if evidence is not _UNSET:
        if not isinstance(evidence, list):
            return _fail("TIBA_SCHEMA_INVALID", "Receipt evidence must be an array.")
        for item in evidence:
            if (
                not isinstance(item, Mapping)
                or not _only_known(item, {"type", "reference", "network", "url", "hash"})
                or not isinstance(item.get("type"), str)
                or not 1 <= len(item["type"]) <= 100
                or not isinstance(item.get("reference"), str)
                or not 1 <= len(item["reference"]) <= 2048
                or ("network" in item and (not isinstance(item["network"], str) or not 1 <= len(item["network"]) <= 100))
                or ("url" in item and not _uri(item["url"]))
                or ("hash" in item and (not isinstance(item["hash"], str) or not _HASH.fullmatch(item["hash"])))
            ):
                return _fail("TIBA_SCHEMA_INVALID", "Receipt contains invalid evidence.")

    is_solana_payment = result == "success" and all(
        action.get(field) == expected
        for field, expected in {
            "protocol": "payment",
            "action": "transfer",
            "resource": "solana:devnet",
            "tool": "transfer_checked",
        }.items()
    )
    if not is_solana_payment:
        return _ok()

    for item in ([] if evidence is _UNSET else evidence):
        reference = item.get("reference") if isinstance(item, Mapping) else None
        if (
            isinstance(reference, str)
            and _SOLANA_BASE58.fullmatch(reference)
            and item.get("type") == "solana_transaction"
            and item.get("network") == "solana-devnet"
            and item.get("url") == f"https://explorer.solana.com/tx/{reference}?cluster=devnet"
        ):
            return _ok()
    return _fail(
        "TIBA_SCHEMA_INVALID",
        "Successful Solana devnet payments require canonical solana_transaction evidence.",
    )


def _validate_scope(scope: Any) -> Check:
    if (
        not isinstance(scope, Mapping)
        or not _only_known(scope, {"actions", "counterparties", "data"})
        or not isinstance(scope.get("actions"), list)
        or not scope["actions"]
        or not isinstance(scope.get("counterparties"), list)
        or not scope["counterparties"]
        or not isinstance(scope.get("data"), Mapping)
        or not _only_known(scope["data"], {"read", "write"})
    ):
        return _fail("TIBA_SCHEMA_INVALID", "Mandate scope must include non-empty actions/counterparties and data rules.")
    for action in scope["actions"]:
        if (
            not isinstance(action, Mapping)
            or not _only_known(action, {"protocol", "action", "resource", "tool"})
            or not all(_selector(action.get(key)) for key in ("protocol", "action", "resource", "tool"))
        ):
            return _fail("TIBA_SCHEMA_INVALID", "Every scope action needs valid protocol/action/resource/tool selectors.")
    if not all(_selector(item) for item in scope["counterparties"]):
        return _fail("TIBA_SCHEMA_INVALID", "Invalid counterparty selector.")
    for direction in ("read", "write"):
        if not isinstance(scope["data"].get(direction), list) or not all(_selector(item) for item in scope["data"][direction]):
            return _fail("TIBA_SCHEMA_INVALID", f"Invalid scope.data.{direction} selector.")
    return _ok()


def _validate_action(action: Any) -> Check:
    if (
        not isinstance(action, Mapping)
        or not _only_known(action, {"protocol", "action", "resource", "tool", "counterparty", "amount", "currency", "data_access"})
        or not all(_selector(action.get(key)) for key in ("protocol", "action", "resource", "tool", "counterparty"))
        or not isinstance(action.get("data_access"), Mapping)
        or not _only_known(action["data_access"], {"read", "write"})
    ):
        return _fail("TIBA_SCHEMA_INVALID", "Receipt action requires exact protocol/action/resource/tool/counterparty/data_access fields.")
    if any(action[key] == "*" for key in ("protocol", "action", "resource", "tool", "counterparty")):
        return _fail("TIBA_SCHEMA_INVALID", "Receipt action selectors must be exact, not wildcards.")
    for direction in ("read", "write"):
        values = action["data_access"].get(direction)
        if not isinstance(values, list) or not all(_selector(item) and item != "*" for item in values):
            return _fail("TIBA_SCHEMA_INVALID", f"Receipt action data_access.{direction} must be exact selectors.")
    if ("amount" in action) != ("currency" in action):
        return _fail("TIBA_SCHEMA_INVALID", "Receipt amount and currency must appear together.")
    if "amount" in action and (not _decimal(action["amount"]) or not isinstance(action["currency"], str) or not _CURRENCY.fullmatch(action["currency"])):
        return _fail("TIBA_SCHEMA_INVALID", "Invalid receipt amount or currency.")
    return _ok()


def verify_mandate(mandate: Any) -> Check:
    if not isinstance(mandate, Mapping) or mandate.get("type") != "tiba.mandate" or mandate.get("version") != "0.1" or not isinstance(mandate.get("id"), str) or not _IDENTIFIER.fullmatch(mandate["id"]) or not isinstance(mandate.get("issuer"), str) or not isinstance(mandate.get("subject"), str) or not _timestamp(mandate.get("issued_at")) or not _timestamp(mandate.get("expires_at")) or not isinstance(mandate.get("delegation"), Mapping) or not isinstance(mandate.get("revocation"), Mapping) or not isinstance(mandate.get("escalation"), Mapping):
        return _fail("TIBA_SCHEMA_INVALID", "Not a complete Tiba v0.1 Mandate.")
    if not _only_known(mandate, {"type", "version", "id", "issuer", "subject", "issued_at", "not_before", "expires_at", "scope", "budget", "delegation", "revocation", "escalation", "extensions", "signature"}):
        return _fail("TIBA_SCHEMA_INVALID", "Mandate has unknown top-level fields.")
    try:
        public_key_from_did(mandate["issuer"])
        public_key_from_did(mandate["subject"])
        public_key_from_did(mandate["revocation"].get("authority"))
    except TibaError as exc:
        return _fail("TIBA_DID_KEY_INVALID", str(exc))
    issued, expiry = _timestamp(mandate["issued_at"]), _timestamp(mandate["expires_at"])
    not_before = _timestamp(mandate.get("not_before")) if "not_before" in mandate else None
    if issued is None or expiry is None or expiry <= issued or ("not_before" in mandate and (not_before is None or not_before > expiry)):
        return _fail("TIBA_SCHEMA_INVALID", "Mandate time window is invalid.")
    check = _validate_scope(mandate.get("scope"))
    if not check.ok:
        return check
    delegation = mandate["delegation"]
    if not _only_known(delegation, {"max_depth", "parent"}):
        return _fail("TIBA_SCHEMA_INVALID", "Delegation has unknown fields.")
    depth = delegation.get("max_depth")
    if not isinstance(depth, int) or isinstance(depth, bool) or not 0 <= depth <= 8:
        return _fail("TIBA_SCHEMA_INVALID", "Invalid delegation max_depth.")
    parent = delegation.get("parent")
    if "parent" in delegation and (
        not isinstance(parent, Mapping)
        or not _only_known(parent, {"id", "hash"})
        or not isinstance(parent.get("id"), str)
        or not _IDENTIFIER.fullmatch(parent["id"])
        or not isinstance(parent.get("hash"), str)
        or not _HASH.fullmatch(parent["hash"])
    ):
        return _fail("TIBA_SCHEMA_INVALID", "Invalid delegation parent reference.")
    revocation = mandate["revocation"]
    if (
        not _only_known(revocation, {"url", "list_id", "authority"})
        or not _uri(revocation.get("url"))
        or not isinstance(revocation.get("list_id"), str)
        or not _IDENTIFIER.fullmatch(revocation["list_id"])
        or not isinstance(revocation.get("authority"), str)
    ):
        return _fail("TIBA_SCHEMA_INVALID", "Invalid revocation configuration.")
    escalation = mandate["escalation"]
    if (
        not _only_known(escalation, {"mode", "url"})
        or escalation.get("mode") not in _ESCALATION_RANK
        or ("url" in escalation and not _uri(escalation["url"]))
    ):
        return _fail("TIBA_SCHEMA_INVALID", "Invalid escalation mode.")
    if "budget" in mandate:
        budget = mandate["budget"]
        if (
            not isinstance(budget, Mapping)
            or not _only_known(budget, {"amount", "currency", "per_action_max"})
            or not _decimal(budget.get("amount"))
            or not isinstance(budget.get("currency"), str)
            or not _CURRENCY.fullmatch(budget["currency"])
            or ("per_action_max" in budget and not _decimal(budget["per_action_max"]))
        ):
            return _fail("TIBA_SCHEMA_INVALID", "Invalid mandate budget.")
    if "extensions" in mandate and not _known_extensions(mandate["extensions"]):
        return _fail("TIBA_UNSUPPORTED_CONSTRAINT", "This verifier does not understand a mandate extension.")
    return verify_object_signature(mandate, mandate["issuer"])


def create_mandate(**input_value: Any) -> dict[str, Any]:
    output = {"type": "tiba.mandate", "version": "0.1", "id": input_value.pop("id", f"mandate:{uuid.uuid4()}"), "issued_at": input_value.pop("issued_at", datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z"))}
    output.update(input_value)
    return output


def sign_mandate(mandate: Mapping[str, Any], signer: Ed25519PrivateKey | str) -> dict[str, Any]:
    signed = sign_object(mandate, signer, str(mandate.get("issuer", "")))
    _raise(verify_mandate(signed))
    return signed


def _selector_allows(parent: str, child: str) -> bool:
    return parent == "*" or parent == child


def _action_allows(rule: Mapping[str, str], action: Mapping[str, str]) -> bool:
    return all(_selector_allows(rule[key], action[key]) for key in ("protocol", "action", "resource", "tool"))


def _every_allowed(child: Sequence[str], parent: Sequence[str]) -> bool:
    return all(any(_selector_allows(allowed, item) for allowed in parent) for item in child)


def _narrower(parent: Mapping[str, Any], child: Mapping[str, Any]) -> Check:
    child_parent = child["delegation"].get("parent")
    if not isinstance(child_parent, Mapping) or child_parent.get("id") != parent["id"] or child_parent.get("hash") != hash_object(parent):
        return _fail("TIBA_CHAIN_INVALID", "Child parent reference does not bind the preceding signed mandate.")
    if child["issuer"] != parent["subject"]:
        return _fail("TIBA_CHAIN_INVALID", "Child issuer must be the parent subject.")
    if child["delegation"]["max_depth"] > parent["delegation"]["max_depth"] - 1:
        return _fail("TIBA_DELEGATION_WIDENED", "Child delegation depth exceeds its parent remainder.")
    if _timestamp(child["issued_at"]) < _timestamp(parent["issued_at"]) or _timestamp(child.get("not_before", child["issued_at"])) < _timestamp(parent.get("not_before", parent["issued_at"])) or _timestamp(child["expires_at"]) > _timestamp(parent["expires_at"]):
        return _fail("TIBA_DELEGATION_WIDENED", "Child lifetime widens parent authority.")
    if not all(any(_action_allows(candidate, rule) for candidate in parent["scope"]["actions"]) for rule in child["scope"]["actions"]) or not _every_allowed(child["scope"]["counterparties"], parent["scope"]["counterparties"]) or not _every_allowed(child["scope"]["data"]["read"], parent["scope"]["data"]["read"]) or not _every_allowed(child["scope"]["data"]["write"], parent["scope"]["data"]["write"]):
        return _fail("TIBA_DELEGATION_WIDENED", "Child scope is not a subset of its parent scope.")
    parent_budget, child_budget = parent.get("budget"), child.get("budget")
    if parent_budget is None and child_budget is not None:
        return _fail("TIBA_DELEGATION_WIDENED", "A child cannot introduce a monetary budget.")
    if parent_budget is not None and child_budget is not None:
        if child_budget["currency"] != parent_budget["currency"] or Decimal(child_budget["amount"]) > Decimal(parent_budget["amount"]) or ("per_action_max" in parent_budget and ("per_action_max" not in child_budget or Decimal(child_budget["per_action_max"]) > Decimal(parent_budget["per_action_max"]))):
            return _fail("TIBA_DELEGATION_WIDENED", "Child budget widens parent budget.")
    if child["revocation"] != parent["revocation"]:
        return _fail("TIBA_DELEGATION_WIDENED", "Child changed revocation control.")
    if _ESCALATION_RANK[child["escalation"]["mode"]] < _ESCALATION_RANK[parent["escalation"]["mode"]] or (child["escalation"].get("url") != parent["escalation"].get("url") and _ESCALATION_RANK[child["escalation"]["mode"]] == _ESCALATION_RANK[parent["escalation"]["mode"]]):
        return _fail("TIBA_DELEGATION_WIDENED", "Child weakened escalation.")
    if "extensions" in child and not _known_extensions(child["extensions"]):
        return _fail("TIBA_UNSUPPORTED_CONSTRAINT", "This verifier does not understand a child extension.")
    return _ok()


def verify_mandate_chain(chain: Any) -> Check:
    if not isinstance(chain, list) or not 1 <= len(chain) <= 9:
        return _fail("TIBA_CHAIN_INVALID", "Mandate chain must contain 1 to 9 signed mandates.")
    for mandate in chain:
        check = verify_mandate(mandate)
        if not check.ok:
            return check
    if chain[0]["delegation"].get("parent") is not None:
        return _fail("TIBA_CHAIN_INVALID", "Root mandate may not have a parent.")
    if len(chain) - 1 > chain[0]["delegation"]["max_depth"]:
        return _fail("TIBA_CHAIN_INVALID", "Chain exceeds root max_depth.")
    for parent, child in zip(chain, chain[1:]):
        check = _narrower(parent, child)
        if not check.ok:
            return check
    return _ok(root=chain[0], leaf=chain[-1])


def sign_revocation_list(value: Mapping[str, Any], signer: Ed25519PrivateKey | str) -> dict[str, Any]:
    return sign_object(value, signer, str(value.get("issuer", "")))


def verify_revocation_list(value: Any, mandate: Mapping[str, Any], at: datetime | None = None) -> Check:
    at = at or datetime.now(timezone.utc)
    if not isinstance(value, Mapping) or value.get("type") != "tiba.revocation_list" or value.get("version") != "0.1" or not isinstance(value.get("id"), str) or not _IDENTIFIER.fullmatch(value["id"]) or value.get("issuer") != mandate["revocation"]["authority"] or value.get("list_id") != mandate["revocation"]["list_id"] or _timestamp(value.get("issued_at")) is None or not isinstance(value.get("revoked"), list):
        return _fail("TIBA_REVOCATION_INVALID", "Invalid revocation list for this mandate.")
    if not _only_known(value, {"type", "version", "id", "issuer", "list_id", "issued_at", "next_update", "revoked", "signature"}):
        return _fail("TIBA_REVOCATION_INVALID", "Revocation list has unknown top-level fields.")
    for entry in value["revoked"]:
        if (
            not isinstance(entry, Mapping)
            or not _only_known(entry, {"mandate_id", "revoked_at", "reason"})
            or not isinstance(entry.get("mandate_id"), str)
            or not _IDENTIFIER.fullmatch(entry["mandate_id"])
            or _timestamp(entry.get("revoked_at")) is None
            or ("reason" in entry and (not isinstance(entry["reason"], str) or len(entry["reason"]) > 256))
        ):
            return _fail("TIBA_REVOCATION_INVALID", "Revocation list contains an invalid entry.")
    signature = verify_object_signature(value, mandate["revocation"]["authority"])
    if not signature.ok:
        return _fail("TIBA_REVOCATION_INVALID", signature.message or "Revocation signature failed.")
    next_update = value.get("next_update")
    if next_update is not None and (_timestamp(next_update) is None or _timestamp(next_update) < at):
        return _fail("TIBA_REVOCATION_STALE", "Revocation list is stale.")
    return _ok()


def _revoked(chain: Sequence[Mapping[str, Any]], revocation_list: Mapping[str, Any] | None, at: datetime) -> Check:
    if revocation_list is None:
        return _ok()
    check = verify_revocation_list(revocation_list, chain[-1], at)
    if not check.ok:
        return check
    entries = {entry.get("mandate_id"): entry.get("revoked_at") for entry in revocation_list["revoked"] if isinstance(entry, Mapping)}
    for mandate in chain:
        revoked_at = entries.get(mandate["id"])
        if _timestamp(revoked_at) is not None and _timestamp(revoked_at) <= at:
            return _fail("TIBA_REVOKED", f"Mandate {mandate['id']} was revoked.")
    return _ok()


def _consumed_budget(receipts: Sequence[Mapping[str, Any]], chain: Sequence[Mapping[str, Any]]) -> list[str]:
    root_id = chain[0]["id"]
    return [receipt["action"]["amount"] for receipt in receipts if receipt.get("result") == "success" and isinstance(receipt.get("action"), Mapping) and "amount" in receipt["action"] and receipt.get("mandate_chain") and receipt["mandate_chain"][0].get("id") == root_id]


def authorize_action(*, mandate_chain: list[dict[str, Any]], action: Mapping[str, Any], at: datetime | str | None = None, revocation_list: Mapping[str, Any] | None = None, require_revocation: bool = False, prior_receipts: Sequence[Mapping[str, Any]] = ()) -> Check:
    chain_check = verify_mandate_chain(mandate_chain)
    if not chain_check.ok:
        return chain_check
    action_check = _validate_action(action)
    if not action_check.ok:
        return action_check
    if isinstance(at, str):
        parsed_at = _timestamp(at)
        if parsed_at is None:
            return _fail("TIBA_SCHEMA_INVALID", "Authorization timestamp must use canonical UTC milliseconds.")
        at = parsed_at
    at = at or datetime.now(timezone.utc)
    if at.tzinfo is None:
        at = at.replace(tzinfo=timezone.utc)
    leaf = chain_check.leaf
    assert leaf is not None
    if _timestamp(leaf.get("not_before", leaf["issued_at"])) > at:
        return _fail("TIBA_NOT_YET_VALID", "Mandate is not effective yet.")
    if _timestamp(leaf["expires_at"]) <= at:
        return _fail("TIBA_EXPIRED", "Mandate has expired.")
    if require_revocation and revocation_list is None:
        return _fail("TIBA_REVOCATION_UNAVAILABLE", "No revocation list was supplied.")
    revoked = _revoked(mandate_chain, revocation_list, at)
    if not revoked.ok:
        return revoked
    if not any(_action_allows(rule, action) for rule in leaf["scope"]["actions"]):
        return _fail("TIBA_SCOPE_DENIED", "Action tuple is not in mandate scope.")
    if not _every_allowed([action["counterparty"]], leaf["scope"]["counterparties"]):
        return _fail("TIBA_COUNTERPARTY_DENIED", "Counterparty is not in mandate scope.")
    if not _every_allowed(action["data_access"]["read"], leaf["scope"]["data"]["read"]) or not _every_allowed(action["data_access"]["write"], leaf["scope"]["data"]["write"]):
        return _fail("TIBA_DATA_DENIED", "Requested data access is not in mandate scope.")
    if "amount" in action:
        for mandate in mandate_chain:
            budget = mandate.get("budget")
            if budget is None:
                return _fail("TIBA_BUDGET_EXCEEDED", "Mandate does not authorize monetary actions.")
            if action["currency"] != budget["currency"]:
                return _fail("TIBA_CURRENCY_MISMATCH", "Action currency does not match mandate budget.")
            if "per_action_max" in budget and Decimal(action["amount"]) > Decimal(budget["per_action_max"]):
                return _fail("TIBA_BUDGET_EXCEEDED", "Action exceeds per-action budget.")
        spent = sum((Decimal(item) for item in _consumed_budget(prior_receipts, mandate_chain)), Decimal(action["amount"]))
        if any(spent > Decimal(mandate["budget"]["amount"]) for mandate in mandate_chain):
            return _fail("TIBA_BUDGET_EXCEEDED", "Action exceeds remaining mandate budget.")
        if leaf["escalation"]["mode"] == "require_confirmation":
            return _fail("TIBA_ESCALATION_REQUIRED", "Mandate requires a fresh human confirmation.")
        return _ok(root=chain_check.root, leaf=leaf, spent=format(spent, "f"))
    if leaf["escalation"]["mode"] == "require_confirmation":
        return _fail("TIBA_ESCALATION_REQUIRED", "Mandate requires a fresh human confirmation.")
    return _ok(root=chain_check.root, leaf=leaf)


def create_receipt(**input_value: Any) -> dict[str, Any]:
    chain = input_value["mandate_chain"]
    if not chain:
        raise TibaError("TIBA_CHAIN_INVALID", "A receipt needs a mandate chain.")
    leaf = chain[-1]
    input_hash = input_value.pop("input_hash", hash_object(input_value.pop("input", None)))
    output_hash = input_value.pop("output_hash", hash_object(input_value.pop("output", None)))
    output = {
        "type": "tiba.receipt",
        "version": "0.1",
        "id": input_value.pop("id", f"receipt:{uuid.uuid4()}"),
        "mandate_id": input_value.pop("mandate_id", leaf["id"]),
        "mandate_hash": input_value.pop("mandate_hash", hash_object(leaf)),
        "executed_at": input_value.pop("executed_at", datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")),
        "input_hash": input_hash,
        "output_hash": output_hash,
    }
    output.update(input_value)
    return output


def sign_receipt(receipt: Mapping[str, Any], signer: Ed25519PrivateKey | str) -> dict[str, Any]:
    signed = sign_object(receipt, signer, str(receipt.get("actor", "")))
    _raise(verify_receipt(signed))
    return signed


def verify_receipt(receipt: Any, *, revocation_list: Mapping[str, Any] | None = None, prior_receipts: Sequence[Mapping[str, Any]] = (), require_revocation: bool = False) -> Check:
    if not isinstance(receipt, Mapping) or receipt.get("type") != "tiba.receipt" or receipt.get("version") != "0.1" or not isinstance(receipt.get("id"), str) or not _IDENTIFIER.fullmatch(receipt["id"]) or not isinstance(receipt.get("mandate_id"), str) or not _IDENTIFIER.fullmatch(receipt["mandate_id"]) or not isinstance(receipt.get("mandate_hash"), str) or not _HASH.fullmatch(receipt["mandate_hash"]) or not isinstance(receipt.get("mandate_chain"), list) or _timestamp(receipt.get("executed_at")) is None or not isinstance(receipt.get("actor"), str) or not isinstance(receipt.get("input_hash"), str) or not _HASH.fullmatch(receipt["input_hash"]) or not isinstance(receipt.get("output_hash"), str) or not _HASH.fullmatch(receipt["output_hash"]) or receipt.get("result") not in ("success", "failure", "denied"):
        return _fail("TIBA_SCHEMA_INVALID", "Not a complete Tiba v0.1 Receipt.")
    if not _only_known(receipt, {"type", "version", "id", "mandate_id", "mandate_hash", "mandate_chain", "action", "input_hash", "output_hash", "result", "reason", "executed_at", "actor", "evidence", "extensions", "signature"}):
        return _fail("TIBA_SCHEMA_INVALID", "Receipt has unknown top-level fields.")
    action = _validate_action(receipt.get("action"))
    if not action.ok:
        return action
    if receipt["result"] == "denied" and (not isinstance(receipt.get("reason"), str) or not _REASON.fullmatch(receipt["reason"])):
        return _fail("TIBA_SCHEMA_INVALID", "Denied receipts need a Tiba error reason.")
    evidence = _validate_evidence(receipt["evidence"] if "evidence" in receipt else _UNSET, action=receipt["action"], result=receipt["result"])
    if not evidence.ok:
        return evidence
    if "extensions" in receipt and not _known_extensions(receipt["extensions"]):
        return _fail("TIBA_UNSUPPORTED_CONSTRAINT", "This verifier does not understand a receipt extension.")
    chain_check = verify_mandate_chain(receipt["mandate_chain"])
    if not chain_check.ok:
        return chain_check
    leaf = chain_check.leaf
    assert leaf is not None
    if receipt["mandate_id"] != leaf["id"] or receipt["mandate_hash"] != hash_object(leaf) or receipt["actor"] != leaf["subject"]:
        return _fail("TIBA_RECEIPT_MANDATE_MISMATCH", "Receipt does not bind the active mandate and actor.")
    signature = verify_object_signature(receipt, receipt["actor"])
    if not signature.ok:
        return signature
    if receipt["result"] == "denied":
        return _ok()
    return authorize_action(mandate_chain=receipt["mandate_chain"], action=receipt["action"], at=receipt["executed_at"], revocation_list=revocation_list, prior_receipts=prior_receipts, require_revocation=require_revocation)


def assert_authorized(**options: Any) -> dict[str, Any]:
    result = authorize_action(**options)
    _raise(result)
    assert result.leaf is not None
    return result.leaf


def assert_verified_receipt(receipt: Any, **options: Any) -> None:
    _raise(verify_receipt(receipt, **options))
