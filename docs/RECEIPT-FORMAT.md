# The receipt format — `quarantine/receipt/v1`

A receipt is the durable output of a Quarantine run: what was executed, what was observed, what was
decided and what was repaired, as one signed document. This file specifies it so that somebody can
**implement a verifier without reading this codebase**. That is the point: a verdict nobody else can check
is an assertion, not evidence.

The reference verifier is [`tools/verify_receipt_standalone.py`](../tools/verify_receipt_standalone.py) —
Python standard library only, importing nothing from this package, checking Ed25519 through `openssl`
rather than through the library that signed. [`scripts/check_receipt_test_vector.py`](../scripts/check_receipt_test_vector.py)
holds this document to the test vector below and runs in CI.

---

## 1. Envelope

A receipt is a JSON object with three members, DSSE-shaped:

```json
{
  "payloadType": "application/vnd.quarantine.receipt+json",
  "payload": "<base64 (standard alphabet) of the canonical payload bytes>",
  "signatures": [ { "keyid": "<16 hex chars>", "sig": "<base64 of the 64-byte Ed25519 signature>" } ]
}
```

## 2. Canonical payload bytes

The bytes that are signed — and that `payload` decodes to — are:

```
json.dumps(payload_object, sort_keys=True, separators=(",", ":")) encoded as UTF-8
```

Two consequences an implementation must get right, because both are load-bearing:

- **No whitespace anywhere**, and keys in ascending code-point order. `{"a": 1, "b": 2}`, never
  `{"a": 1, "b": 2}` with spaces, indentation or a different key order.
- **A valid signature over non-canonical bytes is still invalid.** Canonicality is part of the format, not
  a formatting preference: two implementations that disagree about it will disagree about the signed bytes.
  A verifier that checks only the signature accepts a re-serialised payload the signer never signed —
  test vector case 3 exists for exactly this.

## 3. `keyid`

```
keyid = lowercase_hex( sha256( public_key_pem_bytes ) )[:16]
```

`public_key_pem_bytes` are the bytes of the PEM-encoded public key — the file itself, not a re-encoding of
the key structure. The verifier does not choose the key by `keyid`; it is given a public key and may use
`keyid` to confirm it has the right one.

## 4. Signature

Ed25519 over the canonical payload bytes, raw 64 bytes, base64-encoded. The public key is PEM
`SubjectPublicKeyInfo`.

## 5. Verification algorithm

1. `payloadType` **must** equal `application/vnd.quarantine.receipt+json`. Otherwise: reject.
2. base64-decode `payload`. Reject on failure.
3. For **every** entry in `signatures`: verify `sig` over the decoded bytes with the given public key.
   Reject if any fails. (A receipt with zero signatures is a rejection, not a pass.)
4. Parse the decoded bytes as JSON. Reject on failure.
5. **Re-apply the canonicalisation of §2 and require the result to be byte-identical to the decoded bytes.**
   Reject otherwise. This is the step that catches a payload whose signature happened to be computed over
   non-canonical bytes.
6. Only now read the payload.

A verifier should return a distinguishable failure per step if it can. "Not verified" without a reason is
much less useful to the person holding a receipt.

## 6. Payload

The payload is an object. `spec` is `quarantine/receipt/v1` for this version. Verifiers should treat
unknown fields as forward-compatible additions, and should not require any particular field beyond `spec`
to accept the signature — signature validity and payload semantics are separate questions.

The fields the reference implementation writes, and what they are for, are documented in the README's
[receipt table](../README.md#the-receipt). A verifier that only checks the envelope does not need to
understand any of them.

## 7. Test vector

[`docs/receipt-vector/`](receipt-vector/) contains a signed receipt and two files that **must not** verify,
with the public key but not the private one — the private key was discarded after signing, so the vector
cannot be re-signed.

| file | must it verify? | why the case exists |
|---|---|---|
| [`valid-receipt.json`](receipt-vector/valid-receipt.json) | **yes** | the payload as signed |
| [`tampered-verdict.json`](receipt-vector/tampered-verdict.json) | no | the verdict edited `BLOCK`→`ALLOW` and re-canonicalised, so the signature covers different bytes |
| [`tampered-not-canonical.json`](receipt-vector/tampered-not-canonical.json) | no | the payload is **not** canonical JSON but carries a **valid signature over those exact bytes** — an implementation that only checks the signature accepts this one |

[`public-key.pub.pem`](receipt-vector/public-key.pub.pem) is the key; its `sha256[:16]` is the `keyid` in the
envelope, which is also a check that §3 is implemented correctly.

An implementation is conforming when it accepts case 1 and rejects cases 2 and 3.

## 8. What a receipt does and does not prove

**Proves:** the payload is exactly what was signed, and the signer held the private key matching the public
key you were given. If the payload is canonical, you are reading the same bytes that were signed.

**Does not prove:** that the verdict is *correct*, that the key belongs to anyone in particular, or that the
analysis was independent. The keys here are self-signed and published in this repository; there is no
certificate authority and no third-party attestation. A receipt is evidence that a run happened and was not
altered — it is not a statement about the artifact's safety by anyone but its signer.

This is why the format is documented rather than merely implemented: the value of a receipt is that an
auditor, a customer and a regulator can all check the same artifact with different implementations. That
only works if the format is a specification somebody else can build against.
