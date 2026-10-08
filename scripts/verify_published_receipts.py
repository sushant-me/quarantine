#!/usr/bin/env python3
"""Verify the published receipts with OpenSSL, and prove the verifier rejects tampering.

Why this exists as its own script rather than a line in the README: the repository's strongest
claim is that a verdict can be checked without trusting the code that produced it, and until now
the only place that claim was exercised was on the machine that wrote it. This runs the check
somewhere we do not control — a CI runner — using `openssl` rather than the Python that signed,
and then it tampers with a copy and requires the check to fail.

That last part is the one people skip. A verifier that returns "VERIFIED" for everything passes
every happy-path test ever written.

    python scripts/verify_published_receipts.py
"""

from __future__ import annotations

import base64
import json
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
VERIFIER = ROOT / "tools" / "verify_receipt_standalone.py"

# The receipts a reader is told to verify, from the README's recipe.
PUBLISHED = [
    ("runs/probe/receipt.json", "runs/probe/keys/quarantine.pub.pem", "BLOCK"),
    ("runs/benign/receipt.json", "runs/benign/keys/quarantine.pub.pem", "ALLOW"),
]


def _run(receipt: Path, pub: Path) -> subprocess.CompletedProcess:
    return subprocess.run([sys.executable, str(VERIFIER), str(receipt), "--pub", str(pub)],
                          capture_output=True, text=True, timeout=300)


def main() -> int:
    failures: list[str] = []

    for receipt_rel, pub_rel, expected in PUBLISHED:
        receipt, pub = ROOT / receipt_rel, ROOT / pub_rel
        for path in (receipt, pub):
            if not path.exists():
                failures.append(f"{path.relative_to(ROOT)} is missing")
        if failures:
            continue

        result = _run(receipt, pub)
        verified = "VERIFIED" in result.stdout and "NOT VERIFIED" not in result.stdout
        print(f"{'ok  ' if verified else 'FAIL'} {receipt_rel} verifies under openssl "
              f"(expected {expected})")
        if not verified:
            failures.append(f"{receipt_rel} did not verify: {result.stdout.strip()[-200:]}")

        # The receipt must also say what we think it says, or a valid signature is worthless.
        try:
            envelope = json.loads(receipt.read_text(encoding="utf-8"))
            payload = json.loads(base64.b64decode(envelope["payload"]))
            decided = payload["verdict"]["decided"]
        except Exception as exc:                                 # noqa: BLE001
            failures.append(f"{receipt_rel} could not be decoded: {exc}")
            continue
        if decided != expected:
            failures.append(f"{receipt_rel} says {decided}, expected {expected}")
        else:
            print(f"     payload says {decided}, as expected")

        # And the verifier must reject a payload that has been edited.
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as handle:
            tampered = Path(handle.name)
        try:
            envelope["payload"] = base64.b64encode(json.dumps({
                **payload, "verdict": {**payload["verdict"],
                                       "decided": "ALLOW" if expected != "ALLOW" else "BLOCK"},
            }).encode()).decode()
            tampered.write_text(json.dumps(envelope), encoding="utf-8")
            result = _run(tampered, pub)
            rejected = "NOT VERIFIED" in result.stdout or result.returncode != 0
            print(f"{'ok  ' if rejected else 'FAIL'} tampering with {receipt_rel} is rejected")
            if not rejected:
                failures.append(f"{receipt_rel}: the verifier accepted a tampered payload")
        finally:
            tampered.unlink(missing_ok=True)

    if failures:
        print("\nFAILED:")
        for line in failures:
            print(f"  - {line}")
        return 1
    print(f"\n{len(PUBLISHED)} published receipts verified under openssl; "
          "tampering rejected in every case.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
