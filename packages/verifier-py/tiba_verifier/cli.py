"""Independent, receipt-only Tiba verifier command line interface."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Sequence

from . import public_key_from_did, verify_receipt


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Verify Tiba receipts with only a trusted public did:key and receipt files."
    )
    parser.add_argument("--receipts-dir", required=True, type=Path)
    parser.add_argument("--trusted-actor", required=True, help="Expected active-agent public did:key")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    options = _parser().parse_args(argv)
    try:
        public_key_from_did(options.trusted_actor)
    except Exception as error:
        print(json.dumps({"ok": False, "error": "TIBA_DID_KEY_INVALID", "message": str(error)}))
        return 2

    directory = options.receipts_dir.resolve()
    files = sorted(path for path in directory.glob("receipt*.json") if path.is_file())
    if not files:
        print(json.dumps({"ok": False, "error": "TIBA_RECEIPTS_MISSING", "message": "No receipt*.json files found."}))
        return 2

    verified: list[str] = []
    for path in files:
        try:
            receipt = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as error:
            print(json.dumps({"ok": False, "file": path.name, "error": "TIBA_SCHEMA_INVALID", "message": str(error)}))
            return 1
        if receipt.get("actor") != options.trusted_actor:
            print(json.dumps({"ok": False, "file": path.name, "error": "TIBA_RECEIPT_MANDATE_MISMATCH", "message": "Receipt actor is not the supplied public did:key."}))
            return 1
        check = verify_receipt(receipt)
        if not check.ok:
            print(json.dumps({"ok": False, "file": path.name, "error": check.code, "message": check.message}))
            return 1
        verified.append(path.name)

    print(json.dumps({"ok": True, "trusted_actor": options.trusted_actor, "verified_receipts": verified}, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
