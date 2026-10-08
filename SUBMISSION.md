# SUBMISSION — Quarantine

**The offline clean room for untrusted model artifacts.**
Every model you download is code you did not write. Quarantine runs it where it cannot hurt you, records
what it does, has a local open-weight model read that behaviour against the artifact's own declaration,
blocks what it cannot explain, and repairs what it can — with a signed receipt at the end.

Ten minutes end to end. Start with [`SPIKE-RESULTS.md`](SPIKE-RESULTS.md) if you want the numbers first.

**Before you read on:** the organisers' six minimum requirements and their list of what counts as AI usage are
quoted and mapped, one by one, in [`docs/EVENT-REQUIREMENTS.md`](docs/EVENT-REQUIREMENTS.md) — including the
three rules from their guidelines that shaped this design: **no API keys are provided** (so the model runs
locally), **open-weight only, self-hosted or hosted** (we are stricter: self-hosted only, and the model layer
is one function so a buyer can point it at their own open-weight endpoint), and *"source, license, model, and
key dependencies"* must be easy to verify (so they are stated in the README and checked by
`scripts/check_eligibility.py`).

*Questions for the organisers go to `events@lftechnology.com` — their stated contact.*

---

## 1. The five required items

| # | Required | Where it is |
|---|---|---|
| 1 | Public GitHub repository | this repository — source, tests, corpus generator, evaluation harness |
| 2 | Documentation: README, architecture, technology, limitations | [`README.md`](README.md) · [`SPIKE-RESULTS.md`](SPIKE-RESULTS.md) · [`LIMITATIONS.md`](LIMITATIONS.md) |
| 3 | Working demonstration | `python -m quarantine.cli inspect corpus/probe-custom-generate` — five commands in the README, no API key, no network |
| 4 | Demo video | [`reports/video/quarantine-demo.mp4`](reports/video/quarantine-demo.mp4) — script in [`docs/DEMO-SCRIPT.md`](docs/DEMO-SCRIPT.md), transcript in [`reports/video/transcript.txt`](reports/video/transcript.txt), and an honest note on what the video is in [`reports/video/README.md`](reports/video/README.md) |
| 5 | AI usage disclosure naming `file::function` | [`docs/AI-USAGE.md`](docs/AI-USAGE.md) — machine-checked by `scripts/check_eligibility.py` |

*A separate business proposal — market, pricing, unit economics, regional go-to-market and an honest
intellectual-property position — accompanies this submission as a standalone document; it is deliberately not
in the repository, because the event asks for a product and its evidence, not a plan.*

*Running and verifying are both one command, and verification does not require this codebase: [`tools/verify_receipt_standalone.py`](tools/verify_receipt_standalone.py) is stdlib-only and checks the Ed25519 signature with `openssl`. The public keys are committed so a judge can verify a receipt without trusting us.*

## 2. Why the AI is load-bearing

The challenge's test: *delete the AI call — does the product still do its job?*

**No.** What remains is a syscall trace and an AST capability list. That is exactly the thing that
[demonstrably misses 7 of 8 undeclared artifacts](reports/corpus-eval.md) and
[blocks 4 of 4 real published models](reports/corpus-real-eval.md). The model turns evidence into a decision
(`src/quarantine/semantic/analyst.py::analyse_artifact`) and into a repair
(`src/quarantine/repair/loader.py::synthesize_loader`) — and both are verified by deterministic checks
(grounding against the trace, and output-equivalence after repair).

## 3. What we measured, and what it cost the incumbents

| | Quarantine | picklescan 1.0.5 | fickling 0.1.12 |
|---|---|---|---|
| detection, 9 undeclared artifacts | **9/9** | 2/9 | 2/9 |
| false positives, 4 benign controls | **0** | 0 | 0 |
| false positives, **20 real published models** | **0 blocked** | 0 | **18 (90%)** |
| real models escalated (UNKNOWN, referred to a human) | **0 of 20** | — | — |
| repair produced and capability-clean | **7/7** attempted | — | — |
| repair verified by output-equivalence | **6/7** (one honest refusal) | — | — |
| sandbox escape, 10 primitives | **0 escaped** | — | — |

**We also looked for a bypass and did not find one — see [`reports/scanner-coverage.md`](reports/scanner-coverage.md).**
19 one-pickle probes for standard-library callables that perform network, filesystem, process or
dynamic-code operations, plus 6 benign controls: Quarantine observed the operation **19/19** with
**0/6 false positives**; picklescan's own verdict caught **10/19** while calling `os.getcwd` and
`datetime.now` infected; fickling flagged **all 25 probes and all 6 harmless controls**, so it
carries no discriminating signal here. **No denylist gap that both incumbents miss was found**, and
the pitch does not claim one — the measured difference is coverage of the code path.

**And it was pointed at Nepal, not just at fixtures.** Three real published Nepali-language models
(NepaliBERT, a Nepali MiniLM embedder, and a Nepali-tuned Qwen shipped as **GGUF**) were fetched and run. The
first run **escalated the GGUF model** — because GGUF quantisations are how most Nepali models reach users, and
the reader did not know the format. That is now fixed. Models, counts and limits:
[`docs/NEPAL.md`](docs/NEPAL.md).

**The counterweight is measured too.** On picklescan's *own* published malicious corpus (91 samples, one per
real GHSA advisory) their denylist flags **88 (97%)** and our contained run observes the payload act on
**43 (47%)** — 0 false positives on their 4 benign samples. Their payloads typically name a vulnerable entry
point in a host library and do nothing when loaded alone; ours act on load. **This is not a replacement for a
pickle scanner; it is the other half of the pair** — with the code path (no scanner opens a `.py`) and the
repair (no scanner attempts one) as the parts only this tool covers.
[`reports/third-party-eval.md`](reports/third-party-eval.md)

**Three outcomes, and `UNKNOWN` is not a pass.** Exit codes make it a gate: **0 ALLOW · 1 BLOCK · 2 UNKNOWN**.
Escalation is reserved for cases a human must decide — nothing was observed, the agents disagreed, or the model
was unreachable. Before that outcome existed, an artifact whose dependency was missing was reported ALLOW:
*"we could not run it, so we saw nothing, so it is fine"*.

The incumbents' single catch on the labeled corpus is the only artifact whose payload is a **pickle** — the
only one inside their input set. The other seven payloads live in files neither scanner opens. That is a
**coverage hole, not a detection-logic failure**, and it is version-independent. Meanwhile a real checkpoint
is a zip archive fickling cannot parse, so it warns *"DO NOT TRUST this file"* and exits non-zero on every
ordinary PyTorch model. **Static scanning fails in both directions at once.**

## 4. What this does NOT claim

Copied from [`LIMITATIONS.md`](LIMITATIONS.md) so it is not buried: the malicious corpus and its labels are
ours; the 20 third-party controls are deliberately small models, so they test format handling and false
positives rather than scale; **no live CVE bypass is claimed** — we looked for a denylist gap that both
incumbents miss and did not find one (see [`reports/scanner-coverage.md`](reports/scanner-coverage.md)); one
model size; equivalence is 12 prompts plus a capability check rather than a proof of behavioural equivalence;
the escape attempt is ten primitives rather than a fuzzing campaign; the receipt has not been independently
verified; **`safetensors` is validated but its tensor values are not inspected**, so a poisoned-weights attack
is out of scope; and the repair is verified on 6 of 7 attempts, with the seventh a refusal and weight-only
payloads skipped rather than repaired.

## 5. Run it

```bash
uv venv --python 3.12 .venv
uv pip install --python .venv/bin/python cryptography picklescan fickling jsonschema pytest

./scripts/serve_model.sh &                                   # local open-weight model, no API key
.venv/bin/python scripts/make_corpus.py
PYTHONPATH=src .venv/bin/python scripts/eval_corpus.py       # detection vs the incumbents
PYTHONPATH=src .venv/bin/python scripts/escape_attempt.py    # ten breakout primitives
PYTHONPATH=src .venv/bin/python -m pytest -q                 # 66 tests

# one artifact, the whole loop, offline
PYTHONPATH=src .venv/bin/python -m quarantine.cli inspect corpus/probe-custom-generate --out runs/probe
PYTHONPATH=src .venv/bin/python -m quarantine.cli verify  runs/probe/receipt.json \
        --pub runs/probe/keys/quarantine.pub.pem
```

## 6. Entry-point discipline

Every instruction in this repository is written once. A path that appears in a document and does not exist
is a defect — this project's own history includes exactly that failure mode in a sibling codebase, which is
why `scripts/check_eligibility.py` **resolves** every `path::symbol` named in the disclosure instead of
grepping the text for it.

## 7. Licence

Apache-2.0 — see [`LICENSE`](LICENSE). This is a security tool, not a guarantee: it raises the cost of
shipping a compromised artifact and it does not eliminate the risk.
