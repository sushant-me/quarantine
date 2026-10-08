# Spike results — measured, not claimed

**Date:** 2026-10-08 · **Machine:** 12 threads, 14 GB RAM, RTX 4050 6 GB · **Model:** `qwen2.5-coder-3b-instruct-q4_k_m` on local llama.cpp · **Container:** `python:3.12-slim`, Docker 29.7.2
**Reproduce:** `./scripts/serve_model.sh &` → `python scripts/make_corpus.py` → `python scripts/eval_corpus.py` → `python scripts/escape_attempt.py` → `pytest`

---

## 1. Two headline results

### 1.1 Detection on a labeled corpus of 13 artifacts

Every artifact declares the **same** API (`generate(prompt) -> str`, a pure deterministic transform).
Four ship exactly that. Nine ship something else as well.

| auditor | caught (of 9) | detection rate | false positives (of 4 controls) | FP rate |
|---|---|---|---|---|
| **Quarantine (BLOCK, grounded)** | **9** | **100%** | **0** | **0%** |
| picklescan 1.0.5 | 2 | 22% | 0 | 0% |
| fickling 0.1.12 | 2 | 22% | 0 | 0% |

**Read the incumbents' 2/9 correctly.** The two cases they catch are the two whose payload is a **pickle** —
the only ones inside their input set, and picklescan deserves credit for reading inside zip archives. The
other **seven** payloads live in `custom_generate/generate.py` and `modeling_custom.py`, files neither scanner
opens. That is not a detection-logic failure, it is a **coverage hole**, and it is version-independent.

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

The labeled corpus is ours, so a false-positive rate measured only against it proves little. **Twenty real
repositories published by other people** were fetched (`scripts/fetch_real_models.py`) and run through the
same pipeline — chosen for architecture *and format* variety: zip checkpoints, legacy pickles, safetensors
containers and sharded layouts, plus one genuinely real widely-used model (`google/bert_uncased_L-2_H-128_A-2`)
rather than only fixtures. Every one is expected to be benign; any `BLOCK` is a false positive.

| auditor | false positives (of 20 real models) | what it says |
|---|---|---|
| **Quarantine** | **0 blocked, 0 escalated** | `ALLOW`, grounded, on all twenty |
| picklescan 1.0.5 | 0 | clean on all twenty |
| **fickling 0.1.12** | **18 (90%)** | `exit 2` on nearly every one |

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

### 1.4 The repair path, evaluated across the whole corpus

The repair was previously exercised on one artifact. It is now run end to end on all nine undeclared
artifacts, with every number read back from the **signed receipt** (`scripts/eval_repair.py`) so this measures
what the product emits rather than a parallel code path.

| measure | result |
|---|---|
| blocked by the local model (grounded) | **9/9** |
| repair attempted (needs a grounded BLOCK) | 7/9 |
| repair produced and passed the capability gate | **7/7** |
| repair **verified by output-equivalence** | **6/7** |

**The criterion is now two things, not one.** A repair is accepted only if it produces identical outputs on
**12 prompts** (case, punctuation, unicode, empty string, whitespace, a tab, digits, a newline, and a 300-character
input) **and** performs **zero capability operations** while doing so. The second half is measured from the
audit trace, not from the source: the AST check in `repair/loader.py` proves the code *looks* clean; this proves
nothing of the kind *happened*. On the reference artifact the original performed **2** capability operations
(`file.read /etc/hostname`, `socket.getaddrinfo`) and the repair performed **0**.

**The two non-passes are both honest and both worth saying out loud:**

1. **2 of 9 were not attempted** — `cve-2025-46417-pickle` and `probe-zip-checkpoint` ship no Python. An
   artifact whose payload is a weight file has nothing to rewrite as a loader; repairing it means
   re-serialising the weights (`safetensors`), a different operation. The receipt records
   `skipped_reason: "no shipped Python to repair (payload is a weight file)"`.
2. **1 of 7 was refused, not failed** — `probe-obfuscated` cannot be proven equivalent because **the original
   cannot be executed at all**: its payload raises `gaierror` during import and kills the process. The repaired
   loader is capability-clean and correct, but equivalence with something that will not run cannot be
   established, so the receipt says `"the ORIGINAL artifact could not be executed, so equivalence is NOT
   established"`. Claiming a pass there would have been the dishonest move.

### 1.5 The agent team, and the third outcome

Six roles: **observer** (deterministic), **analyst** / **challenger** / **repairer** (the local model), and
**verifier** / **scribe** (deterministic). They never call each other — each posts to an append-only case file
(`board.jsonl`) and the supervisor routes from what is on it. The whole transcript travels inside the receipt.

`UNKNOWN` is a real outcome, and it is **not a pass**:

| artifact class | verdict | exit | why |
|---|---|---|---|
| artifact hiding a DNS call on load | **BLOCK** | 1 | capability observed and not permitted by the declaration |
| benign control | **ALLOW** | 0 | looked, saw nothing capability-like |
| realistic custom code whose dependency is missing | **UNKNOWN** | 2 | *could not be executed* → escalated to a human |
| a real published checkpoint (torch zip) | **ALLOW** | 0 | the reader now opens the format — and doing so found defect 15 |

Two of those branches exist because of measured failures, documented below as defects 12 and 14. The one that
matters most: **before this outcome existed, the artifact whose dependency was missing was reported `ALLOW`.**
*"We could not run it, so we saw nothing, so it is fine"* is the most dangerous possible default for a security
gate.

On the 13-artifact corpus the agent team reaches **9/9 with zero escalations and zero false positives** — the
adversarial check and the escalation path cost nothing on decidable cases. On the four real published models
**0 of 20 escalate**: the reader opens torch's zip format and validates safetensors, so a benign
checkpoint is now *looked at* and allowed
rather than referred to a human. Getting there introduced defect 15, which the controls caught.

---

## 2. What the reader can open, and why it matters

The single most important fix in this spike is not a new detection: it is that the reader
can now **open the format real models actually ship**.

A modern `pytorch_model.bin` is a **zip archive** containing `archive/data.pkl` plus tensor
storage files. A plain-pickle reader cannot open it, which meant that on the four real
published models **three were escalated** — honest, but a tool that escalates the common
format is not usable in a pipeline.

The reader now detects the zip magic, reads `data.pkl`, and unpickles it under the audit
hook — which is exactly what `torch.load` does. The security question is *what code runs*,
and that code now runs.

**What is stubbed, and why the line is where it is.** A checkpoint's pickle rebuilds tensors
through helpers that live in torch; with torch absent the lookup fails and the whole
unpickling aborts. Those helpers are stubbed — but only by a narrow structural rule
(`is_serialization_helper`): torch's `*Storage` types and `_rebuild*` family, numpy's array
reconstruction, and the standard library's pickle scaffolding (`collections`, `copyreg`,
`types`). **Nothing that can reach the network or the filesystem is ever stubbed**, and
`builtins.eval/exec/open/__import__` are excluded explicitly.

**That line runs in two places, and the second one was found by the third-party controls.**
Reading real checkpoints made them ask for `collections.OrderedDict`,
`torch._utils._rebuild_tensor_v2` and `torch.LongStorage` — and `pickle.find_class` was
counted as evidence, so every legitimate model suddenly looked suspicious. The same
predicate now filters that event, so only a global that is *not* scaffolding counts as
evidence (defect 15 below).

---

## 3. Does the incumbent denylist have holes? (Negative result — and a real one)

The most tempting claim available to this project is *"we detect what the scanners miss"*. So we
tested it directly instead of asserting it: 19 standard-library callables that perform network,
filesystem, process or dynamic-code operations, each built into a one-pickle probe, plus **6
benign controls** (harmless stdlib calls a legitimate pickle makes). Every hostname is under
`.invalid` (RFC 2606) and no filesystem target is harmed — these are probes, not payloads.

`scripts/probe_scanner_coverage.py` · `reports/scanner-coverage.md`

| measure | result |
|---|---|
| Quarantine observed the operation | **19/19** |
| Quarantine false positives on the benign controls | **0/6** |
| picklescan 1.0.5 **called infected** (its own verdict) | **10/19** |
| picklescan **called benign controls infected** | **2/6** |
| fickling 0.1.12 flagged — operations *and* controls | **25/25** |

**What this says, including the part that does not flatter us.** We looked for a callable that
reaches the network or the filesystem while both scanners report clean. **Fickling flagged
everything, so there was no such gap** — a negative result we are publishing rather than burying.
Fickling's 25/25 is not detection: it flags all six harmless controls too, so it carries no
discriminating signal here.

picklescan is more interesting, and reading its *verdict* rather than its "suspicious globals"
count matters. It misses **9 of 19** direct I/O primitives — `socket.gethostbyname`,
`socket.gethostbyaddr`, `http.client.HTTPConnection`, `ftplib.FTP`, `smtplib.SMTP`, `poplib.POP3`,
`imaplib.IMAP4`, `xmlrpc.client.ServerProxy`, `builtins.open` — while calling **`os.getcwd` and
`datetime.datetime.now` infected**. Its denylist is not aligned with capability in either
direction.

Two things follow, and we state both: a denylist gap alone would not settle anything (fickling
catches these by flagging indiscriminately), and **this is still not the product's claim.** The
measured difference the product rests on is the one in §1: the payloads that matter live in
`custom_generate/generate.py` and `modeling_*.py`, files neither scanner opens. This experiment
sharpens the *why* — name-matching cannot see behaviour — without pretending a bypass we cannot
demonstrate.

---

## 4. The corpus

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

## 5. Twenty defects found by running it

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
| 10 | both loaders silently failed to run inside the equivalence proof | `mode_call` called the trace-flush helper, which wrote to a global that only `mode_trace` sets — so the proof reported "outputs differ" instead of a pass | `_flush()` now takes the path as an argument. **Found by tightening the criterion**, which turned what would have been a silent false negative into a hard failure |
| 11 | the pickle-only artifact crashed the CLI with `IndexError` | the repair path indexed `custom_code_files[0]` without checking that any shipped Python exists | skip the repair with a stated reason when there is nothing to rewrite. **Found by running the repair across the whole corpus** rather than one artifact |

**#10 and #11 are the argument for this whole section.** Both were in code that already "worked" on the one
case anyone had looked at. One was hidden by a criterion too weak to notice it; the other by a corpus too
small to contain the case. Neither would have appeared in a demo.

### The defects found while turning the pipeline into an agent team

| # | What broke | Root cause | Fix |
|---|---|---|---|
| 12 | a realistic artifact — custom code whose dependency is not installed — was reported **ALLOW** | nothing was executed, the trace was empty of capability, and an empty trace was treated as a clean bill of health | `Case.escalation_reason`: **nothing observed ⇒ no verdict, escalated**. `UNKNOWN` (exit 2) is now distinct from success |
| 13 | the challenger **overturned a correct BLOCK**, citing real trace ids | a refutation was accepted if it *cited* evidence; nothing checked whether the claim was true | a refutation must now **quote, verbatim, the sentence in the declaration that permits the behaviour** (`_quote_supports_refutation`). A plausible objection that cannot be grounded changes nothing |
| 14 | then the challenger's fix over-corrected: two artifacts were escalated even though a capability had been **observed** before the crash | escalation triggered on *any* execution error, discarding the best evidence in the case | observed now includes *a recorded capability operation*; an artifact that opens a socket and then dies is judged on the socket |

**Three defects in one afternoon, all in code that had passed its tests.** #12 is the same failure mode as a
bug found in a sibling codebase — a path that exists but holds nothing scannable walked nothing, found nothing,
and exited 0 — and it is the reason the third outcome exists here.

### And the defect the fix for the format introduced

| # | What broke | Root cause | Fix |
|---|---|---|---|
| 15 | after the reader learned to open torch zip checkpoints, **every legitimate model started looking suspicious** | `pickle.find_class` was treated as evidence of capability, and a real checkpoint asks for `collections.OrderedDict`, `torch._utils._rebuild_tensor_v2` and `torch.LongStorage` | first fix: filter the serialization scaffolding. **Caught by the third-party negative controls**, not by any hand-written case |
| 16 | the fix for 15 was still wrong: a benign pickle that merely mentions `json.dumps`, `math.sqrt` or `re.compile` was counted as capability, and `datetime.now` tripped it through `builtins.getattr` | we were treating **every** requested global as evidence, not just dangerous ones — and two of those names collide across modules (`re.compile` vs the builtin, `getattr` that the pickle protocol itself emits to reference a method) | the rule is now: **asking for a global is intent, not capability.** Only unambiguous execution/IO globals count, builtins are matched in `builtins`/`_io` only, and protocol-emitted attribute access is excluded. Found by the 6 benign controls in §2 — **the controls again** |
| 17 | scaling the controls to 20 real models: a **safetensors-only repository had nothing to read**, so the modern default format was escalated | the reader only looked for pickle-format weight files | safetensors is now *validated and not executed* — the format has no pickle and no callable, so "nothing can run" is a property of the format rather than a guess |
| 18 | **pointing the tool at the Nepali ecosystem escalated its dominant format** | GGUF is how most Nepali models reach users (six of the top thirty on the Hub are quantisations), and the reader did not know it | `load_gguf` validates the header and metadata framing; a pickle renamed `.gguf` fails the magic check and is escalated, never trusted |
| 19 | a real published model (`rotary-indictrans2`) was **BLOCKed while benign**: its weights loaded, so the case counted as "observed", while its custom code had never run | escalation only fired when *nothing* was observed, so a partial observation slipped through and left the analyst to interpret a `ModuleNotFoundError` as evidence | if shipped Python exists and did not run and no capability was observed, the case escalates regardless of what else loaded (`agents/case.py::Case.code_path_unrun`) |
| 20 | a `BLOCK` could be **grounded by citing an error** — every cited id existed, so the check passed | grounding verified that cited ids *exist*, not that they are *evidence of capability* | `semantic/analyst.py::verdict_is_grounded`: a BLOCK must cite at least one capability event. An error means we could not look |

Twenty defects, and the pattern is consistent: every one was found by a control group, a
third-party artifact, a rate, or a corpus — never by the case anyone was demonstrating.

**#7 and #8 are the most instructive.** Both were *our* fault, both produced a detector that blocked
everything, and neither would have been visible in a demo — a demo shows the case you chose. They were
found only because there was a control group and a rate to compute. That is the argument for the corpus.

---

## 6. What is NOT proven

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
5. **Equivalence is 12 prompts, not a proof.** It now checks 12 inputs *and* that the repaired loader
   performed no capability operation — much stronger than the 3-prompt smoke test it replaced, but still not
   a proof of behavioural equivalence: it cannot see side effects that produce no output, and 12 prompts are
   not a specification.
6. **The escape attempt is ten primitives, not a fuzzing campaign.** A clean table means *these ten*
   failed. It is not a claim that the box cannot be broken, and no kernel exploit was attempted.
7. **No independent receipt verification.** Our own verifier, our own key. Standard primitives, unaudited.
8. **Python only, and zip-format checkpoints are not executed.** ONNX custom ops, GGUF metadata, and
   torch zip archives (the common real format) are read as *unreadable*, not inspected. `safetensors` is
   not even attempted — though it is the format that removes pickle execution by design.
9. **The repair is verified on 6 of 7 attempts, and the seventh is a refusal, not a failure.** It removes
   capability rather than proving absence: a capability that neither the AST nor the trace reveals would pass.
   Repair is also **not attempted for weight-only payloads**, which is a real gap in coverage rather than a
   passing case.
10. **The reader knows four formats; the long tail is longer.** Zip checkpoints, legacy pickles,
    `safetensors` and `gguf` are handled, and all 20 English controls plus all 3 Nepali ones are decided
    rather than escalated. ONNX, TensorFlow/Flax (`.msgpack`, `.h5`), `.keras` and `.tflite` are still not
    opened at all — and for `safetensors` and `gguf` the container is validated, not inspected for poisoned
    values. The remaining risk is therefore not the format list but the values (item 15).
11. **The agent team costs three model calls per blocked artifact** (analyst, challenger, repairer) — roughly
    35 s wall-clock on a 3B model. Escalation short-circuits before any model call, which is why the unknown
    path is also the fast path.

---

## 7. Timing (this machine, model warm)

| stage | per artifact |
|---|---|
| static pass (inventory + both scanners + AST) | ~1.0 s |
| contained execution (one container) | ~0.7 s |
| semantic verdict | 10–15 s |
| **whole 12-artifact evaluation** | **≈ 3 minutes** |

---

## 8. Next

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
