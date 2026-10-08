# Event requirements — mapped, and verified by a script

Source: the Frogtoberfest 2026 site itself (`frogtoberfest.lftechnology.com`, home + guidelines + FAQ),
read 2026-10-08. The wording below is the organisers'; the mapping is ours.

`scripts/check_eligibility.py` enforces the parts of this that a script can enforce — it resolves every
`path::symbol` named in the disclosure by **importing the file**, and verifies every repo path named in any
document exists. It fails the build otherwise. Its output is quoted at the bottom of this file.

---

## 1. The six minimum requirements

> *"The minimum requirements every submission must meet to be eligible for judging:"*

| # | The organisers' requirement | Where this repository satisfies it | How to verify |
|---|---|---|---|
| 1 | **Public repository** — *"source code is public and includes everything needed to run and understand the solution"* | the whole thing; `corpus-real/` is fetched by a script rather than vendored, and `scripts/` regenerates every report | `## Run it` in [`README.md`](../README.md) |
| 2 | **Documentation** — *"README, architecture overview, technology details, and limitations/future improvements are all present and complete"* | README (architecture + technology), [`LIMITATIONS.md`](../LIMITATIONS.md), [`SPIKE-RESULTS.md`](../SPIKE-RESULTS.md) | four sections of the README, plus `LIMITATIONS.md` items 1–15 |
| 3 | **Working demo** — *"a functional demonstration of the solution and its key capabilities is provided"* | one command runs the whole team; the corpus and the 20 real models reproduce the numbers | `## Run it` |
| 4 | **Demo video** — *"a short demo showing the problem, solution, workflow, and value"* | [`reports/video/quarantine-demo.mp4`](../reports/video/quarantine-demo.mp4) (2:31), built from real command output by `scripts/build_demo_video.py` — no mock-ups | `reports/video/README.md` lists what it covers |
| 5 | **AI does real work** — *"AI processes, transforms, or reasons over data as part of core logic — not just generates a displayed response"* | the verdict gates the pipeline and the exit code; see §2 | `docs/AI-USAGE.md`, `tests/` |
| 6 | **AI-usage disclosure** — *"a short written statement naming the exact file/function where AI output is consumed programmatically"* | [`docs/AI-USAGE.md`](AI-USAGE.md) — names three AI entry points and what consumes each | the checker imports and resolves every `path::symbol` in it |

## 2. Their list of what counts as AI usage — we hit all six

| Their qualifier | Ours |
|---|---|
| *Structured extraction* — "AI reads unstructured input … and outputs structured data (JSON, fields) that code consumes downstream" | `semantic/analyst.py::analyse_artifact` turns a syscall trace plus source into a schema-constrained verdict object |
| *AI classifies or scores something and the system acts differently based on that output* | that verdict selects the next agent and the process **exit code** (0 allow / 1 block / 2 escalate) |
| *AI selects and invokes tools or APIs … with results fed back in* | `repair/loader.py::synthesize_loader` produces candidate loader bodies; the harness assembles them, a deterministic AST gate rejects any residual capability, **and the rejection is fed back** for a bounded number of retries |
| *Output of one AI call becomes input to another step* | analyst → challenger → repairer, routed by `agents/supervisor.py::run_case` |
| *AI's answer is conditioned on data the system retrieved and assembled* | the prompt is assembled from the captured trace, the AST capability graph and the execution status — the numbers in it are computed by the harness, not by the model |
| *AI processes a batch or stream of records and results are aggregated, diffed, scored* | `scripts/eval_corpus.py` runs the whole corpus and aggregates into the published matrices |

## 3. Their list of what does NOT qualify — and why this is not that

| Disqualifier | Ours |
|---|---|
| "output goes straight to the user, nothing downstream consumes it" | the verdict is consumed by the supervisor, the receipt, and the exit code |
| "no processing happens after generation" | generation is followed by AST gating, a contained re-run and an output-equivalence comparison |
| "AI wasn't part of the product, only the submission artifact" | delete the three model calls and there is no verdict, no challenge, and no repair |
| "the repo is essentially a system prompt plus an API call" | five deterministic passes, a Docker containment layer, a trace format, a corpus, and a signed receipt sit around the model |

## 4. Two rules that shaped the design

1. **"financial support or API keys will *not* be provided."** So the model runs **locally**: llama.cpp with
   `qwen2.5-coder-3b-instruct-q4_k_m`, no key, no account, no egress. `scripts/serve_model.sh` is the whole
   hosting story, and the demo video runs with the network off.
2. **"only open-source or open-weight AI qualifies (e.g. Llama, Mistral, Qwen, DeepSeek, self-hosted or via a
   hosted provider). Proprietary APIs … are discouraged."** We are stricter than required: **self-hosted
   only**, enforced by `check_eligibility.py::check_no_vendor_inference`, which fails the build if a
   proprietary inference vendor is referenced anywhere in `src/` or `scripts/`.

   Being stricter is deliberate and it is a *product* decision, not just a compliance one: an artifact
   scanner that phones home to a proprietary API cannot be pointed at a customer's private model registry.
   The model layer is one function — `src/quarantine/llm.py::chat` — so a buyer can point it at any
   open-weight endpoint they already run.

## 5. The reference project the organisers name

Their guidelines hold up **[Munder Difflin](https://github.com/chaitanyagiri/munder-difflin)** as *"a strong
reference for what 'Build with AI' should look like"*, describing three motifs:

- *"a central orchestrator agent reads incoming requests, routes work to the right agent, and escalates only
  the items that need a human — spend, destructive operations, scope changes."*
- *"agents … read from and write to a shared 'hive': per-agent memory, a mailbox system, and a blackboard,
  all backed by plain files in a local git repo."*
- *"Each spawned agent CLI runs as a real terminal process."*

Our mapping, stated precisely: we have the **routing** (`agents/supervisor.py::run_case` — a policy, not a
prompt), the **escalation-only-for-humans** rule (nothing observed / agents disagree / model unreachable),
and the **blackboard** (`agents/blackboard.py::Blackboard`, append-only JSONL, so the receipt can carry the
whole transcript).

**Where we differ, so nobody has to discover it:** our agents are *roles over one local model*, not separate
agent-CLI processes in separate terminals. The coordination pattern is the same; the process topology is not.
What is a real process is the artifact under test — it runs in its own throwaway container, which is the
point of this particular product.

## 6. Questions and correspondence

`events@lftechnology.com` — the organisers' stated contact for questions. Registration ran September 16–29,
and the timeline places **ideation and problem identification in Week 1**, with building in Weeks 2–3; the
registration repo *"will be used to keep track of submissions throughout the challenge."* Demo Day is
October 30 in Kathmandu valley, and **at least one team member must be physically present**.
