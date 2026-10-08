#!/usr/bin/env python3
"""Check the published receipt test vector — the negative cases included.

`docs/RECEIPT-FORMAT.md` specifies the format so somebody else can implement a verifier without
reading this codebase. A specification with no test vector is guesswork: the two implementations
agree until they meet a case nobody wrote down. This checks the vector the document points at,
using the standalone verifier (stdlib plus openssl, importing nothing from this package), and it
requires the negative cases to FAIL verification, not merely to look suspicious.

    python scripts/check_receipt_test_vector.py
"""

from __future__ import annotations

import base64
import hashlib
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
VECTOR = ROOT / "docs" / "receipt-vector"
VERIFIER = ROOT / "tools" / "verify_receipt_standalone.py"
PAYLOAD_TYPE = "application/vnd.quarantine.receipt+json"
# The implementation writes this string; the vector and the document must match it.
SPEC = "quarantine/receipt/v1"

# file, must it verify, and why that case exists
CASES = [
    ("valid-receipt.json", True,
     "the signed payload, unmodified"),
    ("tampered-verdict.json", False,
     "the verdict edited BLOCK->ALLOW and re-canonicalised, so the signature covers other bytes"),
    ("tampered-not-canonical.json", False,
     "a payload that is NOT canonical JSON but carries a valid signature over those exact bytes - "
     "an implementation that only checks the signature accepts this one"),
]


def main() -> int:
    problems: list[str] = []
    pub = VECTOR / "public-key.pub.pem"
    if not pub.exists():
        print(f"FAIL the test vector is missing ({pub})")
        return 1

    # The keyid is derived, so an implementer can check the derivation from the document alone.
    expected_keyid = hashlib.sha256(pub.read_bytes()).hexdigest()[:16]
    envelope = json.loads((VECTOR / "valid-receipt.json").read_text(encoding="utf-8"))
    declared_keyid = envelope["signatures"][0]["keyid"]
    if declared_keyid != expected_keyid:
        problems.append(f"keyid mismatch: envelope says {declared_keyid}, "
                        f"sha256(public key)[:16] is {expected_keyid}")
    else:
        print(f"ok   keyid is sha256(public-key.pub.pem)[:16] = {expected_keyid}")

    if envelope.get("payloadType") != PAYLOAD_TYPE:
        problems.append(f"payloadType is {envelope.get('payloadType')!r}")

    for name, should_verify, why in CASES:
        path = VECTOR / name
        if not path.exists():
            problems.append(f"{name} is missing")
            continue
        result = subprocess.run(
            [sys.executable, str(VERIFIER), str(path), "--pub", str(pub)],
            capture_output=True, text=True, timeout=300)
        verified = "VERIFIED" in result.stdout and "NOT VERIFIED" not in result.stdout
        ok = verified is should_verify
        verdict = "verifies" if verified else "rejected"
        print(f"{'ok  ' if ok else 'FAIL'} {name:30} {verdict:9} (expected "
              f"{'verify' if should_verify else 'rejection'})")
        if not ok:
            problems.append(f"{name}: {why} - but it {verdict}")
        elif not should_verify:
            print(f"       rejected for the right reason: {why}")

    # The valid payload must decode, or the vector is not usable by an implementer.
    payload = json.loads(base64.b64decode(envelope["payload"]))
    if payload.get("spec") != SPEC:
        problems.append(f"the vector's payload carries spec {payload.get('spec')!r}")
    else:
        print(f"ok   the payload is canonical JSON for spec {payload['spec']} "
              f"and decodes to {sorted(payload)[:4]}...")

    if problems:
        print("\nFAILED:")
        for line in problems:
            print(f"  - {line}")
        return 1
    print(f"\n{len(CASES)} vector cases behave as the format document says.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
