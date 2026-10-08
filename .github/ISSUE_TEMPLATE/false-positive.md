---
name: False positive — a benign artifact we blocked or escalated
about: Quarantine called your model artifact suspicious. Tell us, and it becomes a control case.
title: "false positive: <artifact>"
labels: false-positive
---

**A false positive is the most valuable bug report this project can receive.** The corpus grows by adding
benign artifacts that a scanner gets wrong — that is the whole mechanism, and it is why the 20 real published
models and the 5 Nepali/Indic models are in the repository at all. You do not have to know why it happened.

## What was judged

- **Artifact** (name, and a link if it is public):
- **Verdict you got** (`BLOCK` or `UNKNOWN`):
- **What you expected** (`ALLOW`, presumably):

## The receipt, if you have one

The receipt is the fastest path to a fix: it contains the trace, the verdict, the evidence the model relied
on, and the noise floor that was subtracted.

```
quarantine inspect <artifact> --out runs/your-name
# attach runs/your-name/receipt.json  (it is self-contained and signed; check what you attach)
```

## How you ran it

- Quarantine version: `quarantine --version` or the `tool.version` inside the receipt
- Image: default `python:3.12-slim`, or `QUARANTINE_IMAGE=quarantine-analysis:latest`
- Model: `qwen2.5-coder-3b-instruct-q4_k_m` (the default) or another
- Was the artifact's shipped Python executed? The receipt says: `behaviour.execution`

## What the artifact actually does

If you wrote it, or you know: does it read files outside its own directory, touch the network, or spawn
anything? A one-line description is enough — we are adding it as a *control*, not auditing you.

---

*If you would rather not attach the artifact itself, the receipt plus the declaration's text is usually
enough to reproduce it. Details of how we handle reported artifacts are in
[`SECURITY.md`](SECURITY.md).*
