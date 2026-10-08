"""Signed behavioural receipts.

The receipt is the product. A verdict in a terminal window changes nothing; a
signed, self-contained record of *what was run, what happened, what was decided
and what was repaired* is something a security team can file.

Format is DSSE-shaped: a base64 payload plus detached signature over those exact
bytes, so the envelope is verifiable without trusting the tool that made it.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

PAYLOAD_TYPE = "application/vnd.quarantine.receipt+json"


def canonical(payload: dict) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def generate_keypair(key_path: Path) -> Path:
    key_path.parent.mkdir(parents=True, exist_ok=True)
    private = Ed25519PrivateKey.generate()
    key_path.write_bytes(private.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ))
    os.chmod(key_path, 0o600)
    pub_path = key_path.with_suffix(".pub.pem")
    pub_path.write_bytes(private.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ))
    return pub_path


def _private(key_path: Path) -> Ed25519PrivateKey:
    return serialization.load_pem_private_key(key_path.read_bytes(), password=None)


def keyid(pub_pem: bytes) -> str:
    return hashlib.sha256(pub_pem).hexdigest()[:16]


def sign_receipt(payload: dict, key_path: Path) -> dict:
    priv = _private(key_path)
    body = canonical(payload)
    pub_pem = priv.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return {
        "payloadType": PAYLOAD_TYPE,
        "payload": base64.b64encode(body).decode(),
        "signatures": [{
            "keyid": keyid(pub_pem),
            "sig": base64.b64encode(priv.sign(body)).decode(),
        }],
    }


def verify_receipt(envelope: dict, pub_path: Path) -> bool:
    """True only if the bytes are signed by this key and are canonical JSON."""
    if envelope.get("payloadType") != PAYLOAD_TYPE:
        return False
    raw = base64.b64decode(envelope["payload"])
    pub = serialization.load_pem_public_key(pub_path.read_bytes())
    if not isinstance(pub, Ed25519PublicKey):
        return False
    for sig in envelope.get("signatures", []):
        try:
            pub.verify(base64.b64decode(sig["sig"]), raw)
        except Exception:
            return False
    # the payload must be exactly canonical, or the signature covers different bytes
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError:
        return False
    return canonical(parsed) == raw
