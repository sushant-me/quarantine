# Quarantine — spike

**The offline clean room for untrusted model artifacts.**
Every model you download is code you did not write. Quarantine runs it where it cannot hurt you,
records what it does, has a local open-weight model read that behaviour against the artifact's own
declaration, blocks what it cannot explain, and repairs what it can — with a signed receipt at the end.

This directory is a **working spike**, not the final submission repo. It exists to answer one
question with evidence: *does the core loop actually work, offline, on open weights?*

---

## Run it

```bash
uv venv --python 3.12 .venv
uv pip install --python .venv/bin/python cryptography picklescan fickling jsonschema pytest

./scripts/serve_model.sh &                       # local open-weight model, no API key
.venv/bin/python scripts/make_corpus.py          # rebuild the 12 labeled artifacts
PYTHONPATH=src .venv/bin/python scripts/eval_corpus.py      # detection vs the incumbents
PYTHONPATH=src .venv/bin/python scripts/fetch_real_models.py            # 4 real published models
PYTHONPATH=src .venv/bin/python scripts/eval_corpus.py --dir corpus-real --label benign
PYTHONPATH=src .venv/bin/python scripts/eval_repair.py      # repair + equivalence, whole corpus
PYTHONPATH=src .venv/bin/python scripts/escape_attempt.py   # ten breakout primitives

# one artifact, the whole loop
PYTHONPATH=src .venv/bin/python -m quarantine.cli inspect corpus/probe-custom-generate --out runs/probe
PYTHONPATH=src .venv/bin/python -m quarantine.cli verify  runs/probe/receipt.json \
        --pub runs/probe/keys/quarantine.pub.pem

PYTHONPATH=src .venv/bin/python -m pytest -q     # 66 tests
```

## The agent team

Six roles. **Three use the local model; three are deterministic code** — a model decides what evidence
*means*, code decides what was *observed* and whether a claim is admissible. They never call each other: each
posts to an append-only case file and the supervisor routes from what is on it.

| Agent | Kind | File | Job |
|---|---|---|---|
| observer | deterministic | `sandbox/execute.py`, `static/scan.py` | execute it contained, network off, and record the trace |
| **analyst** | AI | `agents/roles.py::analyst` | ALLOW / BLOCK / UNKNOWN, with evidence cited by trace id |
| **challenger** | AI | `agents/roles.py::challenger` | try to **refute** the analyst — and only by quoting the declaration |
| **repairer** | AI | `agents/roles.py::repairer` | write the replacement function bodies |
| verifier | deterministic | `proof/equivalence.py::compare` | identical outputs **and** zero capability operations |
| scribe | deterministic | `receipt.py` | sign the receipt, transcript included |

Routing lives in `agents/supervisor.py::run_case` and is a policy, not a prompt. Three branches exist purely to
avoid the worst outcome for a security gate — saying "fine" when we did not look:

- **nothing observed** → escalated. Before this rule existed, an artifact whose dependency was missing was
  reported ALLOW. That was a false negative in the most dangerous direction.
- **the agents disagree** and the challenger *grounded* its objection → escalated; the supervisor does not
  pick a winner.
- **the model was unreachable** → escalated; an outage must never become an approval.

Exit codes make it usable as a gate: **0 ALLOW · 1 BLOCK · 2 UNKNOWN**. `2` is not `0`.

```
   observer ──trace──▶ analyst ──BLOCK──▶ challenger ──refuted?──▶ supervisor
                         │                    │                        │
                         │ ALLOW              │ no admissible          │ escalate to a human
                         ▼                    ▼ refutation             ▼  (UNKNOWN, exit 2)
                      receipt             repairer ──▶ verifier ──▶ receipt (exit 0/1)
```

Signed by `src/quarantine/receipt.py` (Ed25519, DSSE-shaped envelope), verifiable by anyone with the public
key. The receipt carries the whole agent transcript, so a reviewer sees which agent said what, in order.

## What the reader can open

Three real formats, three different questions. A modern `pytorch_model.bin` is a **zip archive** holding
`archive/data.pkl` plus tensor storage: the reader detects the zip magic, reads `data.pkl`, and unpickles it
under the audit hook — which is what `torch.load` does, and where the code execution lives. Legacy plain
pickles are read directly. `safetensors` and `gguf` containers are **validated and not executed**, because
neither format has a pickle or a callable in it — that check is what stops the modern default formats from
being escalated, and it says nothing about the tensor *values*, which is a different threat: see
[`LIMITATIONS.md`](LIMITATIONS.md) item 15.

Unpickling a real checkpoint needs torch's tensor-rebuild helpers, which are not installed, so a narrow
structural rule stubs them: torch's `*Storage` types and `_rebuild*` family, numpy's array reconstruction, and
the standard library's pickle scaffolding (`collections`, `copyreg`, `types`) — see
`src/quarantine/sandbox_runner.py::is_serialization_helper`. **Nothing that can reach the network or the
filesystem is ever stubbed**, and `builtins.eval/exec/open/__import__` are excluded explicitly.

The same predicate runs a second time, host-side, in `src/quarantine/events.py::capability_events`: a
`pickle.find_class` for scaffolding is not evidence of capability, or every legitimate model would look
suspicious the moment we could read it. That second use was found by the third-party controls, not by a
hand-written case.

## Why the box is the product

```
docker run --rm --network none --read-only --cap-drop ALL \
  --security-opt no-new-privileges --user <you> --workdir /work \
  --pids-limit 128 --memory 512m --cpus 1 --tmpfs /tmp:rw,size=64m
```

One measured consequence worth knowing: dropping **all** capabilities also removes
`CAP_DAC_OVERRIDE`, so root inside the container can no longer read files it does not own. The first
run failed with `Permission denied` on the harness for exactly that reason — the container now runs
as the invoking unprivileged user.

## The scanner-coverage experiment

`scripts/probe_scanner_coverage.py` builds 19 one-pickle probes for standard-library callables that
perform network, filesystem, process or dynamic-code operations, plus 6 benign controls, and asks the
same three questions of each: does picklescan flag it, does fickling, and does our contained run observe
the operation? Everything is benign by construction — hostnames under `.invalid`, no filesystem target
harmed. Results are in `reports/scanner-coverage.md`, including the negative result: **no denylist gap
that both incumbents miss was found**, so no bypass is claimed.

## The corpus

| Artifact | What it is |
|---|---|
| `corpus/benign-tiny-model` | the control: declared and shipped behaviour match, so the auditor must say ALLOW |
| `corpus/probe-custom-generate` | declared as a pure text transform; ships a `custom_generate/generate.py` that, on load, reads `/etc/hostname` and puts it into a DNS query for a `.invalid` hostname |

The probe is **not malware**. `probe.invalid` is reserved by RFC 2606 and can never resolve; the
artifact exists so the trace has a real out-of-artifact read and a real network attempt to show.

## For the Nepal community

The challenge is about the Nepali open-source community, so the tool was pointed at it: three real published
Nepali-language models (NepaliBERT, a Nepali MiniLM embedder, and a Nepali-tuned Qwen shipped as GGUF) were
fetched and run through the pipeline. **The first run escalated the GGUF model** — and the reason is the shape
of the ecosystem: GGUF quantisations are how most Nepali models reach users, and the reader did not know the
format. It does now, validated rather than executed.

[`docs/NEPAL.md`](docs/NEPAL.md) has the models, the counts, the finding, and what this does *not* claim.
`scripts/fetch_nepali_models.py` reproduces the set with the exact files it needs — a naive fetch of one
quantisation repository is 5.7 GB.

## Technology, licence and dependencies

Stated plainly because the organisers ask that *"source, license, model, and key dependencies"* be easy to
verify:

| | |
|---|---|
| **Licence** | Apache-2.0 ([`LICENSE`](LICENSE)) |
| **Model** | `qwen2.5-coder-3b-instruct-q4_k_m` (Apache-2.0), served by local **llama.cpp** on `127.0.0.1` — the same runtime Ollama and LM Studio wrap. No API key, no account, no egress. `scripts/serve_model.sh` is the entire hosting story. |
| **Language** | Python 3.12, standard library only for the analysis path |
| **Containment** | Docker (`python:3.12-slim`), `--network none --read-only --cap-drop ALL --security-opt no-new-privileges --pids-limit 128 --memory 512m --cpus 1` |
| **Signing** | Ed25519 via `cryptography` (receipt only) |
| **Dev/test** | `pytest`, `picklescan`, `fickling` and `huggingface_hub` are measurement and control tools — never imported by the analysis path |
| **Vendored** | nothing; `corpus-real/` is fetched by [`scripts/fetch_real_models.py`](scripts/fetch_real_models.py) |

[`requirements.txt`](requirements.txt) pins the single runtime dependency (the receipt signer);
[`requirements-dev.txt`](requirements-dev.txt) pins the testing and *measurement* tools — kept separate on
purpose, because the tool's own behaviour must not depend on the scanners it is measured against.
`scripts/check_eligibility.py` additionally fails the build if a proprietary inference vendor is referenced
anywhere in `src/` or `scripts/`.

## Contributing and security

[`CONTRIBUTING.md`](CONTRIBUTING.md) explains the evidence bar — a change that adds a detection needs the
artifact that proves it, and a claim of improvement needs the measurement that shows it.
[`SECURITY.md`](SECURITY.md) is the disclosure policy; a containment failure is treated as the most serious
bug this tool can have.

## Status

See [`SPIKE-RESULTS.md`](SPIKE-RESULTS.md) for what was measured, what failed, and what is still
unproven. Nothing in this directory is a claim until it is in that file.
