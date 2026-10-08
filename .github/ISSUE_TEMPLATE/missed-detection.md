---
name: Missed detection — a malicious artifact we allowed
about: Quarantine called a malicious artifact clean. This is the other half of the corpus.
title: "missed detection: <artifact>"
labels: missed-detection
---

**This is a security-relevant report.** If you believe an artifact is malicious and Quarantine returned
`ALLOW` (exit 0), say so — and please do not attach a live payload to a public issue.

## What was judged

- **Artifact** (name, public link, or a description if it is not public):
- **Verdict you got** (`ALLOW`):
- **What you believe it does:**

## Please do not attach live malware

Describe the capability instead: *"on load it reads `~/.aws/credentials` and posts it to a host it resolves
at import time"* is enough for us to build a benign replica that reproduces the behaviour, and that replica
is what goes into the corpus. If you have a sample you think we must see, use the private channel in
[`SECURITY.md`](SECURITY.md).

## Why it may have been allowed

Two known and documented reasons, both in [`LIMITATIONS.md`](LIMITATIONS.md) — worth checking before
filing:

1. **The payload did not act.** Behavioural observation sees behaviour; an artifact that *names* a vulnerable
   entry point in a host library and calls nothing on load has nothing to observe. This is the reason our
   number on picklescan's own corpus is 43/91 and theirs is 88/91.
2. **The code path never ran.** If the shipped Python needs a dependency the image does not have, the case
   should escalate to `UNKNOWN` (exit 2) rather than allow — if it returned `ALLOW` in that situation, that
   is a real bug and we want it.
