# SUBMISSION — Quarantine

**The offline clean room for untrusted model artifacts.**
Every model you download is code you did not write. Quarantine runs it where it cannot hurt you, records
what it does, has a local open-weight model read that behaviour against the artifact's own declaration,
blocks what it cannot explain, and repairs what it can — with a signed receipt at the end.

Ten minutes end to end. Start with [`SPIKE-RESULTS.md`](SPIKE-RESULTS.md) if you want the numbers first.

---

## 1. The five required items

| # | Required | Where it is |
|---|---|---|
| 1 | Public GitHub repository | this repository — source, tests, corpus generator, evaluation harness |
| 2 | Documentation: README, architecture, technology, limitations | [`README.md`](README.md) · [`SPIKE-RESULTS.md`](SPIKE-RESULTS.md) · [`LIMITATIONS.md`](LIMITATIONS.md) |
| 3 | Working demonstration | `python -m quarantine.cli inspect corpus/probe-custom-generate` — five commands in the README, no API key, no network |
| 4 | Demo video | `docs/DEMO-SCRIPT.md` (the script; the recording is produced from it) |
| 5 | AI usage disclosure naming `file::function` | [`docs/AI-USAGE.md`](docs/AI-USAGE.md) — machine-checked by `scripts/check_eligibility.py` |

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
| detection, 8 undeclared artifacts | **8/8** | 1/8 | 1/8 |
| false positives, 4 benign controls | **0** | 0 | 0 |
| false positives, 4 **real published models** | **0** | 0 | **4/4** |
| sandbox escape, 10 primitives | **0 escaped** | — | — |

The incumbents' single catch on the labeled corpus is the only artifact whose payload is a **pickle** — the
only one inside their input set. The other seven payloads live in files neither scanner opens. That is a
**coverage hole, not a detection-logic failure**, and it is version-independent. Meanwhile a real checkpoint
is a zip archive fickling cannot parse, so it warns *"DO NOT TRUST this file"* and exits non-zero on every
ordinary PyTorch model. **Static scanning fails in both directions at once.**

## 4. What this does NOT claim

Copied from [`LIMITATIONS.md`](LIMITATIONS.md) so it is not buried: the malicious corpus and its labels are
ours; the third-party controls are tiny models; **no live CVE bypass is claimed** (current picklescan catches
our pickle pattern); one model size; equivalence is a three-prompt smoke test; the escape attempt is ten
primitives rather than a fuzzing campaign; the receipt has not been independently verified; Python only, and
zip-format checkpoints are recorded as unreadable rather than executed; the repair path was exercised on one
artifact.

## 5. Run it

```bash
uv venv --python 3.12 .venv
uv pip install --python .venv/bin/python cryptography picklescan fickling jsonschema pytest

./scripts/serve_model.sh &                                   # local open-weight model, no API key
.venv/bin/python scripts/make_corpus.py
PYTHONPATH=src .venv/bin/python scripts/eval_corpus.py       # detection vs the incumbents
PYTHONPATH=src .venv/bin/python scripts/escape_attempt.py    # ten breakout primitives
PYTHONPATH=src .venv/bin/python -m pytest -q                 # 30 tests

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
