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

PYTHONPATH=src .venv/bin/python -m pytest -q     # 36 tests
```

## The five passes

| Pass | File | What it does |
|---|---|---|
| 1 Static | `src/quarantine/static/scan.py` | file inventory + hashes, the incumbent scanners, and an AST capability graph |
| 2 Behavioural | `src/quarantine/sandbox/execute.py` + `sandbox_runner.py` | executes the shipped code in Docker with `--network none`, read-only root, all capabilities dropped, and a CPython audit hook (PEP 578) recording every sensitive operation |
| 3 Semantic | `src/quarantine/semantic/analyst.py::analyse_artifact()` | the local model reads declared vs actual and returns a schema-constrained verdict whose evidence it cites by trace id |
| 4 Repair | `src/quarantine/repair/loader.py::synthesize_loader()` | the local model writes a sanitized loader; it is rejected if any forbidden capability remains |
| 5 Proof | `src/quarantine/proof/equivalence.py::compare()` | original and sanitized loaders run against the same prompts in the same box; identical outputs or the repair is rejected |

Signed by `src/quarantine/receipt.py` (Ed25519, DSSE-shaped envelope), verifiable by anyone with the public key.

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

## The corpus

| Artifact | What it is |
|---|---|
| `corpus/benign-tiny-model` | the control: declared and shipped behaviour match, so the auditor must say ALLOW |
| `corpus/probe-custom-generate` | declared as a pure text transform; ships a `custom_generate/generate.py` that, on load, reads `/etc/hostname` and puts it into a DNS query for a `.invalid` hostname |

The probe is **not malware**. `probe.invalid` is reserved by RFC 2606 and can never resolve; the
artifact exists so the trace has a real out-of-artifact read and a real network attempt to show.

## Status

See [`SPIKE-RESULTS.md`](SPIKE-RESULTS.md) for what was measured, what failed, and what is still
unproven. Nothing in this directory is a claim until it is in that file.
