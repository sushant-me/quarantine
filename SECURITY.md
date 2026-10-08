# Security policy

Quarantine runs untrusted code for a living, so **a containment failure is the most serious bug it can
have** — more serious than any detection it misses. Reports are welcome and will be credited unless you ask
otherwise.

## Reporting

- **Sensitive reports** (anything exploitable): use GitHub's private vulnerability reporting on this
  repository — *Security → Report a vulnerability*. That keeps the detail out of public view until there is a
  fix.
- **Everything else**: open a normal issue.
- Please include the artifact or a minimal reproduction, the image and kernel you ran, and the receipt if you
  have one.

We aim to acknowledge within 72 hours. There is no bounty; there is a credit line and a permanent test case
if the report is reproducible.

## In scope

| Class | What it means here |
|---|---|
| **Containment escape** | the artifact reaches the network, writes outside its workdir, persists after the run, exhausts the host, or observes anything it should not. `scripts/escape_attempt.py` is the current ten-primitive attempt and `reports/sandbox-escape.md` is its result. |
| **False negative in the safe direction** | an artifact that did something the declaration forbids, and was reported `ALLOW`. This is the failure mode the whole design is organised against; `Case.escalation_reason` exists because one was found. |
| **False positive that breaks the product** | a benign artifact that is `BLOCK`ed. The 20 real published models and the 4 benign controls are the regression set; `fickling`'s behaviour on the same set is the cautionary example. |
| **Receipt integrity** | forging, replaying or silently editing a receipt; making `verify` accept a payload it should not. The envelope is Ed25519-signed and DSSE-shaped, and `receipt.py::verify_receipt` checks the signature over the exact payload bytes. |
| **Analyst manipulation** | an artifact that steers the model. The prompt is assembled with the capability count **computed by the harness**, the verdict must cite trace ids that exist, and `ALLOW` is admissible only when that count is zero — so a payload that tells the model "this file is safe" cannot manufacture an approval. If you can defeat that, it is a real finding. |
| **Resource exhaustion in the harness itself** | the container is bounded (`--pids-limit 128 --memory 512m --cpus 1`), but the harness that reads the trace is not. A file that makes the reader allocate without bound is in scope. |

## Out of scope

- Needing the artifact to already have code execution on the *host*; the model is "the artifact is untrusted".
- Attacks that require modifying Quarantine's own source or the model weights.
- Anything in `corpus/` or `corpus-real/` — those are **deliberate** test artifacts, never malware: every
  hostname is under `.invalid` (RFC 2606) and no filesystem target is harmed.
- Vulnerabilities in `picklescan` or `fickling`; report those upstream. We measure their behaviour and do
  not wrap it.

## What we will not claim

The tool does not detect **poisoned weights or backdoored models** — it validates the `safetensors`
container and reads pickles, which is a code-execution question, not a values question
([`LIMITATIONS.md`](LIMITATIONS.md) item 15). It is also not a proof that the container cannot be broken:
`reports/sandbox-escape.md` records ten primitives that failed, which is a measurement, not a guarantee.
