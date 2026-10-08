#!/usr/bin/env python3
"""Verify a Quarantine receipt **without trusting Quarantine** — or its dependencies.

This file is deliberately standalone:

  * it imports **nothing** from `quarantine/`, and no third-party package at all,
  * it checks the Ed25519 signature with **`openssl`** — a different implementation, in a
    different language, by different authors, than the Python that produced the signature.

That is the whole point. A signature you can only check with the tool that made it proves
very little; the useful claim is that a third party with a public key and a copy of the JSON
can decide for themselves. It is also the check we kept listing as a limitation.

    python tools/verify_receipt_standalone.py runs/probe/receipt.json \
           --pub runs/probe/keys/quarantine.pub.pem

Exit code 0 verified, 1 not. Everything it prints is derived from the files it was given.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

PAYLOAD_TYPE = "application/vnd.quarantine.receipt+json"


def canonical(payload: dict) -> bytes:
    """The exact serialisation the signature is computed over."""
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def openssl_verify(pub_pem: Path, message: bytes, signature: bytes) -> tuple[bool, str]:
    """Ed25519 verification via the openssl CLI, not via Python."""
    binary = shutil.which("openssl")
    if not binary:
        return False, "openssl not found — cannot verify independently"
    with tempfile.TemporaryDirectory() as tmp:
        msg_path = Path(tmp) / "payload.bin"
        sig_path = Path(tmp) / "sig.bin"
        msg_path.write_bytes(message)
        sig_path.write_bytes(signature)
        proc = subprocess.run(
            [binary, "pkeyutl", "-verify", "-pubin", "-inkey", str(pub_pem),
             "-rawin", "-in", str(msg_path), "-sigfile", str(sig_path)],
            capture_output=True, text=True, timeout=60)
        out = (proc.stdout + proc.stderr).strip().splitlines()
        detail = out[-1] if out else ""
        return proc.returncode == 0, detail


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("receipt")
    ap.add_argument("--pub", required=True, help="the Ed25519 public key (PEM)")
    ap.add_argument("--quiet", action="store_true")
    args = ap.parse_args()

    def say(*parts: object) -> None:
        if not args.quiet:
            print(*parts)

    envelope = json.loads(Path(args.receipt).read_text(encoding="utf-8"))
    pub_pem = Path(args.pub)
    failures: list[str] = []

    # 1. envelope shape
    if envelope.get("payloadType") != PAYLOAD_TYPE:
        failures.append(f"payloadType is {envelope.get('payloadType')!r}, expected {PAYLOAD_TYPE!r}")
    signatures = envelope.get("signatures") or []
    if not signatures:
        failures.append("no signatures in the envelope")

    # 2. the payload decodes, and is canonical JSON
    try:
        raw = base64.b64decode(envelope["payload"], validate=True)
    except (KeyError, binascii.Error) as exc:
        print(f"FAIL  payload is not valid base64: {exc}")
        return 1
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError as exc:
        print(f"FAIL  payload is not JSON: {exc}")
        return 1
    if canonical(payload) != raw:
        failures.append("payload is not canonical JSON — it was edited after signing, or "
                        "serialised differently")
    else:
        say("ok    payload is canonical JSON (re-serialising it reproduces the signed bytes)")

    # 3. the keyid is the one this key would produce, so the envelope names its key honestly
    wanted = hashlib.sha256(pub_pem.read_bytes()).hexdigest()[:16]
    for sig in signatures:
        if sig.get("keyid") and sig["keyid"] != wanted:
            failures.append(f"keyid {sig['keyid']!r} does not match the public key given ({wanted})")
    say(f"ok    keyid matches the public key ({wanted})")

    # 4. the signature, verified by openssl
    verified = False
    for sig in signatures:
        try:
            blob = base64.b64decode(sig["sig"], validate=True)
        except (KeyError, binascii.Error):
            failures.append("a signature is missing or not base64")
            continue
        ok, detail = openssl_verify(pub_pem, raw, blob)
        say(f"{'ok   ' if ok else 'FAIL'}  openssl: {detail}")
        verified = verified or ok
    if not verified:
        failures.append("no signature verified against this public key")

    # 5. report what was signed, so verification is also informative
    verdict = payload.get("verdict", {})
    artifact = payload.get("artifact", {})
    say("")
    say(f"  artifact   {artifact.get('name')}  tree={str(artifact.get('tree_sha256'))[:16]}")
    say(f"  verdict    {verdict.get('decided')}"
        + ("  (escalated)" if verdict.get("escalated") else ""))
    say(f"  model      {(payload.get('model') or {}).get('name')}")
    say(f"  image      {((payload.get('behaviour') or {}).get('container') or {}).get('image')}")

    print()
    if failures:
        print(f"NOT VERIFIED — {len(failures)} problem(s):")
        for item in failures:
            print(f"  - {item}")
        return 1
    print("VERIFIED — signed by the holder of this key, and the payload is unmodified.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
