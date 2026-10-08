# Spike results — measured, not claimed

**Date:** 2026-10-08 · **Machine:** 12 threads, 14 GB RAM, RTX 4050 6 GB · **Model:** `qwen2.5-coder-3b-instruct-q4_k_m` on local llama.cpp · **Container:** `python:3.12-slim`, Docker 29.7.2
**Reproduce:** `./scripts/serve_model.sh &` → `python scripts/make_corpus.py` → `python scripts/eval_corpus.py` → `python scripts/escape_attempt.py` → `pytest`

---

## 1. Two headline results

### 1.1 Detection on a labeled corpus of 12 artifacts

Every artifact declares the **same** API (`generate(prompt) -> str`, a pure deterministic transform).
Four ship exactly that. Eight ship something else as well.

| auditor | caught (of 8) | detection rate | false positives (of 4 controls) | FP rate |
|---|---|---|---|---|
| **Quarantine (BLOCK, grounded)** | **8** | **100%** | **0** | **0%** |
| picklescan 1.0.5 | 1 | 12% | 0 | 0% |
| fickling 0.1.12 | 1 | 12% | 0 | 0% |

**Read the incumbents' 1/8 correctly.** The single case they catch is `cve-2025-46417-pickle` — the
only artifact in the corpus whose payload is a **pickle**, i.e. the only one inside their input set.
picklescan caught it via its denylist (`dangerous globals: 1`, `ssl.get_server_certificate`); fickling
exited non-zero. The other seven payloads live in `custom_generate/generate.py` and `modeling_custom.py`,
files neither scanner opens. That is not a detection-logic failure, it is a **coverage hole**, and it is
version-independent.

### 1.2 The containment attempt

Ten breakout primitives, run inside exactly the box the artifacts get:

**0 of 10 succeeded.**

| probe | outcome | mechanism |
|---|---|---|
| write to the read-only rootfs | blocked | `Errno 30 Read-only file system` |
| read `/etc/shadow` as an unprivileged user | blocked | `Errno 13 Permission denied` |
| read a host file that was not mounted | blocked | `Errno 2 No such file or directory` |
| `mount(2)` a filesystem | blocked | `Errno 1 Operation not permitted` |
| `unshare(CLONE_NEWUSER)` | blocked | `Errno 1 Operation not permitted` |
| `chroot(2)` | blocked | `Errno 1 Operation not permitted` |
| become uid 0 | blocked | `Errno 1 Operation not permitted` |
| open a raw socket (CAP_NET_RAW) | blocked | `Errno 1 Operation not permitted` |
| connect to the host's model server | blocked | `Errno 111 Connection refused` |
| resolve a public name | blocked | `Errno -3 Temporary failure in name resolution` |

Identity inside the box: `uid 1000, euid 1000, pid 1`. Full report: `reports/sandbox-escape.md`.

### 1.3 Third-party negative controls — real published models

The labeled corpus is ours, so a false-positive rate measured only against it proves little. Four **real
repositories published by other people** were fetched (`scripts/fetch_real_models.py`) and run through the
same pipeline. Every one is expected to be benign; any `BLOCK` is a false positive.

| auditor | false positives (of 4 real models) | what it says |
|---|---|---|
| **Quarantine** | **0** | `ALLOW`, grounded, on all four |
| picklescan 1.0.5 | 0 | clean on all four |
| **fickling 0.1.12** | **4 (100%)** | `exit 2` on every one |

**The fickling result is the finding, and it is fair to state it precisely.** A real checkpoint
(`pytorch_model.bin`) is a **zip archive**, not a bare pickle — `file` confirms it, and fickling cannot
parse it. What fickling then does is print:

> *"Fickling failed to parse this pickle file. Error: No pickle files detected. Parsing errors might be
> indicative of a maliciously crafted pickle file. DO NOT TRUST this file without performing further
> analysis!"*

and **exit 2**. Its caution is defensible — an unparseable artifact genuinely is worth distrusting. But the
operational consequence is that a CI gate built on it **blocks every ordinary PyTorch checkpoint**, with an
alarming message. A scanner that flags everything carries no information.

Quarantine's own handling of that same format is recorded honestly rather than hidden: the plain-pickle
reader cannot open a zip-format checkpoint, so the run emits `weights.unreadable: UnpicklingError` — and
that event is deliberately **not** a capability event, because it is our reader's limitation, not the
artifact's behaviour (`test_weights_unreadable_is_context_not_evidence`). The verdict was still `ALLOW`,
grounded, on a genuinely benign artifact.

**The two incumbents fail in opposite directions**, which is the whole argument: on the code path neither
scanner reads, they miss 7 of 8 undeclared artifacts; on the format they cannot parse, one of them blocks
everything. Behaviour is the only common ground.

---

## 2. The corpus

`scripts/make_corpus.py` generates it deterministically; `corpus/MANIFEST.json` is the label file. All
hostnames are under `.invalid` (RFC 2606) and can never resolve — **nothing here is malware.**

| artifact | truth | category |
|---|---|---|
| `benign-tiny-model` | benign | control |
| `benign-typing-only` | benign | control |
| `benign-two-functions` | benign | control |
| `benign-unicode` | benign | control |
| `probe-custom-generate` | undeclared | network at import |
| `probe-subprocess` | undeclared | process at import |
| `probe-env-exfil` | undeclared | environment → DNS |
| `probe-file-read` | undeclared | `/etc/passwd` → DNS |
| `probe-lazy-trigger` | undeclared | network only when `generate()` is called |
| `probe-obfuscated` | undeclared | base64 + `exec` at import |
| `probe-modeling-file` | undeclared | same probe as `modeling_*.py` |
| `cve-2025-46417-pickle` | undeclared | pickle whose global performs name resolution |

A single case end to end (`probe-custom-generate`): static pass finds `socket` in the AST; the contained
run records `import socket` → `file.read /etc/hostname` → `socket.getaddrinfo <hex>.probe.invalid`; the
local model returns **BLOCK**, grounded, citing exactly those events; the repair removes `_sync`; the
equivalence proof shows identical outputs on the fixed prompts; the receipt is signed and verifies.

---

## 3. Nine defects found by running it

Each of these was invisible to reading. Numbering continues from the first spike.

| # | What broke | Root cause | Fix |
|---|---|---|---|
| 1 | `from quarantine.static.pass import ...` — SyntaxError | `pass` is a Python keyword | renamed modules |
| 2 | container could not read the harness | `--cap-drop ALL` also drops `CAP_DAC_OVERRIDE` — the hardening working | run as the invoking user |
| 3 | picklescan reported "not clean" on a clean artifact | my check grepped for the word `Infected`; picklescan prints `Infected files: 0` | parse the summary into numbers |
| 4 | repair failed | a 1.5B model degenerated into endless `import` lines | moved to a code model |
| 5 | repair failed again | the 3B model removed the malicious call but kept `import socket` | gate feeds rejection back; model writes bodies, harness writes boilerplate |
| 6 | the signed receipt named the wrong model | the name came from an env default, not the server | read the model id back from `/v1/models` |
| 7 | **100% false positives on the controls** | `compile`/`exec` audit events fire for every ordinary module body, so a benign file looked like dynamic-code execution | record only while the artifact is actually running, and drop interpreter-internal events |
| 8 | **still 100% false positives** | my own harness event `weights.load` appeared in the trace as if the artifact had done it | stop recording harness bookkeeping as evidence |
| 9 | benign artifacts returned UNKNOWN/BLOCK on an **empty** trace | the decision rules were buried in prose and the model over-triggered | harness now computes the capability-event count and states it; the prompt is a numbered procedure; an ALLOW is admissible only when the harness independently saw zero capability events |

**#7 and #8 are the most instructive.** Both were *our* fault, both produced a detector that blocked
everything, and neither would have been visible in a demo — a demo shows the case you chose. They were
found only because there was a control group and a rate to compute. That is the argument for the corpus.

---

## 4. What is NOT proven

1. **The malicious set and its labels are ours.** Eight undeclared artifacts were written by us. Four real
   published models now cover the *negative* side, so the false-positive finding is third-party evidence —
   but detection on self-authored payloads is weak evidence, and a hostile reviewer is right to say so.
   What this does show is that the harness works, that the incumbent coverage hole is real, and that one
   incumbent blocks real models outright.
2. **The third-party controls are tiny models.** `bert-tiny`, `tiny-gpt2`, `tiny-random-bert`,
   `tiny-random-gpt2` — real repositories, but small and simple. Real production artifacts have more moving
   parts, and none of these ships custom Python.
3. **Only the pickle case is a published-CVE pattern**, and it is reproduced faithfully in shape, not as a
   live exploit. Crucially, **current picklescan catches it** — so this corpus does *not* show Quarantine
   beating picklescan on pickles. It shows that pickles are only one of the two code paths.
4. **One model size.** Only Qwen2.5-Coder-3B. The 1.5B general model failed at repair; 7B+ untried.
5. **Equivalence is still 3 prompts.** A smoke test, not a proof of behavioural equivalence.
6. **The escape attempt is ten primitives, not a fuzzing campaign.** A clean table means *these ten*
   failed. It is not a claim that the box cannot be broken, and no kernel exploit was attempted.
7. **No independent receipt verification.** Our own verifier, our own key. Standard primitives, unaudited.
8. **Python only, and zip-format checkpoints are not executed.** ONNX custom ops, GGUF metadata, and
   torch zip archives (the common real format) are read as *unreadable*, not inspected. `safetensors` is
   not even attempted — though it is the format that removes pickle execution by design.
9. **The repair path was exercised on one case**, and it removes capability rather than proving absence —
   an obfuscated capability the AST cannot see would pass.

---

## 5. Timing (this machine, model warm)

| stage | per artifact |
|---|---|
| static pass (inventory + both scanners + AST) | ~1.0 s |
| contained execution (one container) | ~0.7 s |
| semantic verdict | 10–15 s |
| **whole 12-artifact evaluation** | **≈ 3 minutes** |

---

## 6. Next

1. Reproduce `GHSA-93mv-x874-956g` and `CERT VU#290`/`CVE-2026-80047` as *current-version* bypass cases —
   the pickle case here is caught by today's picklescan, so a case that still defeats it is the honest test.
2. Add third-party artifacts (real hub models) as negative controls so the FP rate is not measured only
   against our own benign cases.
3. Extend equivalence from 3 prompts to a per-API prompt set with a stated tolerance.
4. Try a 7B coder and record repair success for both sizes.
5. Have someone else verify a receipt on a machine that did not produce it.

---

*Raw evidence: `reports/corpus-eval.json`, `reports/corpus-eval.md`, `reports/sandbox-escape.md`,
`reports/eval-runs/<artifact>/{static.json,trace.jsonl,exec.json}`, `runs/probe/`, `runs/benign/`.*
