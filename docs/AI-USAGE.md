# AI usage disclosure

**Required by the challenge:** *"a short written statement naming the exact file/function where AI output is
consumed programmatically."* This is that statement, and it is machine-checked —
`scripts/check_eligibility.py` parses every `path::symbol` in this file, **imports the file and resolves the
symbol**, and fails the build if one does not exist.

---

## 1. Models used

**Open-weight only. No proprietary inference endpoint is called anywhere in this repository** — not for the
core logic, not for embeddings, not for a secondary classification step. `scripts/check_eligibility.py` scans
every Python file under `src/` and `scripts/` and reports none.

| | |
|---|---|
| model | `qwen2.5-coder-3b-instruct-q4_k_m` (Apache-2.0), served by local **llama.cpp** on `127.0.0.1` |
| transport | `src/quarantine/llm.py::chat` — **the only place that sends inference requests**; all three AI call sites (analyst, challenger, repairer) go through it, and no other file in `src/` opens a connection to run a model. Until this was fixed the analyst and the repairer each held a private HTTP client, which made this row false — defect 29 in `SPIKE-RESULTS.md`. `src/quarantine/modelinfo.py::resolve_model` also reaches the server, but only reads `/v1/models` so the receipt names the model that actually answered. No API key, no vendor, no egress. |
| name recorded | read back from the server's `/v1/models` by `src/quarantine/modelinfo.py::resolve_model`, never a default |

The receipt records which model answered, because a receipt that names the wrong model is a false record.

---

## 2. The agent team

Six roles. **Three use the model; three are deterministic code.** The split is the design, not a detail: a
model decides what the evidence *means*, and code decides what was *observed* and whether a claim is
admissible. No agent's output is taken on trust.

| Agent | Kind | File | What it does |
|---|---|---|---|
| **observer** | deterministic | `src/quarantine/sandbox/execute.py::run_trace` · `src/quarantine/static/scan.py::static_pass` | executes the artifact contained, with the network off, and records the trace |
| **analyst** | AI | `src/quarantine/agents/roles.py::analyst` | decides ALLOW / BLOCK / UNKNOWN from the declaration plus the trace |
| **challenger** | AI | `src/quarantine/agents/roles.py::challenger` | tries to **refute** the analyst, and may only succeed by quoting the declaration verbatim |
| **repairer** | AI | `src/quarantine/agents/roles.py::repairer` | writes the surviving function bodies of a replacement loader |
| **verifier** | deterministic | `src/quarantine/proof/equivalence.py::compare` | re-runs both loaders: identical outputs **and** zero capability operations |
| **scribe** | deterministic | `src/quarantine/receipt.py::sign_receipt` | assembles and signs the receipt, including the whole transcript |

They do not call each other. Each reads the shared case file and posts a note; the supervisor decides who runs
next from what is on the board — `src/quarantine/agents/blackboard.py::Blackboard` (append-only JSONL) and
`src/quarantine/agents/supervisor.py::run_case`. The full transcript travels inside the receipt, so a reviewer
can see which agent said what, in order.

### How each AI output is consumed programmatically

**1. `src/quarantine/agents/roles.py::analyst`** — wraps
`src/quarantine/semantic/analyst.py::analyse_artifact`, which returns a schema-constrained object
`{verdict, declared_matches_behaviour, mechanism, evidence_ids[], confidence}`.

Consumed by:
- `src/quarantine/agents/supervisor.py::run_case` — the verdict **gates the pipeline**. Only a grounded
  `BLOCK` routes to the challenger and then the repairer; an ungrounded verdict is escalated.
- `src/quarantine/cli.py::cmd_inspect` — it becomes the receipt's verdict and the process **exit code**
  (0 allow, 1 block, 2 unknown), which is what makes this usable as a CI gate.
- `scripts/eval_corpus.py::evaluate` — it is the measured quantity in every evaluation report.

**2. `src/quarantine/agents/roles.py::challenger`** — returns `{refuted, objection, permitting_quote,
evidence_ids[], confidence}`.

Consumed by `src/quarantine/agents/supervisor.py::run_case`, which escalates when the refutation is
**admissible** — meaning it cites trace ids that exist *and* quotes a sentence that actually appears in the
declaration (`src/quarantine/agents/roles.py::_quote_supports_refutation`). A plausible objection that cannot
be grounded changes nothing and is recorded as an attempt. Without that check, the first run of this agent
overturned a correct BLOCK by asserting, with real trace ids, that the declaration permitted a DNS lookup.

**3. `src/quarantine/agents/roles.py::repairer`** — wraps
`src/quarantine/repair/loader.py::synthesize_loader`. The model writes the bodies; the harness writes the
`def` lines and indentation.

Consumed by:
- `src/quarantine/cli.py::cmd_inspect` — the source is written to `loader_sanitized.py` and passed to the
  verifier; a candidate that still carries a capability is rejected by
  `src/quarantine/repair/loader.py::forbidden_in_source` and the rejection is fed back to the model.
- `src/quarantine/proof/equivalence.py::compare` — has the final word.

### Deterministic teammates that keep the AI honest

| Rule | Where |
|---|---|
| a verdict must cite trace ids that exist | `src/quarantine/semantic/analyst.py::analyse_artifact` |
| an `ALLOW` is admissible only if the harness counted **zero** capability events | `src/quarantine/events.py::capability_events` |
| **nothing observed ⇒ no verdict**, escalated to a human | `src/quarantine/agents/case.py::Case` |
| a refutation must quote the declaration | `src/quarantine/agents/roles.py::_quote_supports_refutation` |
| a repair must be output-equivalent **and** capability-free at runtime | `src/quarantine/proof/equivalence.py::compare` |
| a model outage must never become an ALLOW | `src/quarantine/agents/supervisor.py::run_case` |
| only serialization scaffolding is stubbed — **never** anything that can do I/O | `src/quarantine/sandbox_runner.py::is_serialization_helper` |
| scaffolding globals are not evidence; `builtins.eval/open/__import__` still are | `src/quarantine/events.py::capability_events` |

---

## 3. Why this is not a chat UI with an API call

The challenge's test: *"if you deleted the AI call from your codebase, would the product still do its job?"*
It would not. What remains is a syscall trace and an AST capability list — exactly what
[demonstrably misses 7 of 8 undeclared artifacts](reports/corpus-eval.md). Deleting the analyst leaves nothing
that turns evidence into a decision; deleting the challenger leaves no adversarial check; deleting the
repairer leaves a block with no path forward. Each is a separate model invocation whose output is parsed,
validated and routed on by code.
