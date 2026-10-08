# AI usage disclosure

**Required by the challenge:** *"a short written statement naming the exact file/function where AI output is
consumed programmatically."* This is that statement, and it is machine-checked —
`scripts/check_eligibility.py` parses every `path::symbol` in this file and resolves it, so a name here that
does not exist fails the build.

## 1. Models used

**Open-weight only. No proprietary inference endpoint is called anywhere in this repository** — not for the
core logic, not for embeddings, not for a secondary classification step. `scripts/check_eligibility.py`
greps every Python file under `src/` and `scripts/` for vendor endpoints and reports none.

| | |
|---|---|
| model | `qwen2.5-coder-3b-instruct-q4_k_m` (Apache-2.0), served by local **llama.cpp** on `127.0.0.1` |
| transport | `POST /v1/chat/completions` against a local server; no API key, no vendor, no egress |
| how the name is recorded | read back from the server's `/v1/models` by `src/quarantine/modelinfo.py::resolve_model`, never from a default (`src/quarantine/modelinfo.py`) |

The receipt records which model answered, because a receipt that names the wrong model is a false record.
That bug was found and fixed during the spike (`SPIKE-RESULTS.md`, defect 6).

## 2. The two AI entry points, and what consumes their output

### 2.1 The semantic verdict

```
src/quarantine/semantic/analyst.py::analyse_artifact
```

Given the artifact's declared behaviour, its shipped code, the captured behavioural trace and the static
capability map, a local model returns a schema-constrained object:
`{verdict: ALLOW|BLOCK|UNKNOWN, declared_matches_behaviour, mechanism, evidence_ids[], confidence}`.

**Consumed programmatically by:**

- `src/quarantine/cli.py::cmd_inspect` — the verdict **gates the pipeline**: only a grounded `BLOCK`
  triggers the repair pass, and `BLOCK`/`ALLOW` are downgraded to `UNKNOWN` when the answer is not grounded.
- `src/quarantine/cli.py::cmd_inspect` — the same verdict is written into the signed receipt payload under
  `verdict`, so it is part of the durable evidence.
- `scripts/eval_corpus.py::evaluate` — the verdict is the measured quantity in the corpus evaluation
  (`reports/corpus-eval.md`).

Delete this call and **no artifact is ever judged**: the pipeline has a trace and a capability list and
nothing that turns them into a decision or a gate.

### 2.2 The repair

```
src/quarantine/repair/loader.py::synthesize_loader
```

The same class of model writes the surviving functions of a sanitized loader. The harness owns the `def`
lines and indentation; the model owns the bodies and the decision about what survives.

**Consumed programmatically by:**

- `src/quarantine/cli.py::cmd_inspect` — the generated source is written to `loader_sanitized.py` and passed
  to the proof step; a candidate that still carries a forbidden capability is rejected and the rejection is
  fed back to the model for a bounded number of attempts.
- `src/quarantine/proof/equivalence.py::compare` — has the final word: the repaired loader is accepted only
  if it produces identical outputs to the original on a fixed prompt set.

Delete this call and **no artifact is repaired** — the block stands and there is nothing to unblock the build.

## 3. What the AI is not allowed to do

These are enforced in code, not promised in prose:

| Rule | Where it is enforced |
|---|---|
| never invent evidence | `analyse_artifact` requires every `evidence_ids` entry to exist in the trace; an ungrounded answer is retried once and then recorded as `UNKNOWN` |
| never receive the network | the trace is captured in a container run with `--network none` (`src/quarantine/sandbox/execute.py`) |
| never decide on its own that the artifact is clean | an `ALLOW` is admissible only when the harness independently counted **zero** capability events (`src/quarantine/events.py::capability_events`) |
| never write a loader that keeps a capability | `src/quarantine/repair/loader.py::forbidden_in_source` parses the candidate and rejects it |
| never be trusted about behaviour | `src/quarantine/proof/equivalence.py::compare` re-runs both loaders and compares outputs |

## 4. Why this is not a chat UI with an API call

The challenge's test is: *"if you deleted the AI call from your codebase, would the product still do its
job?"* It would not. What remains is a syscall trace and an AST capability list — which is precisely the
thing that [demonstrably misses 7 of 8 undeclared artifacts](reports/corpus-eval.md) and
[blocks 4 of 4 real published models](reports/corpus-real-eval.md). The AI is the layer that turns evidence
into a decision, and it is verified by deterministic checks at both ends.
