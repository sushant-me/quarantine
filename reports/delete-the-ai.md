# The Core Test, measured: what is left if you delete the AI call

*"if you deleted the AI call from your codebase, would the product still do its job?"* — the organisers' own baseline check.

Same artifacts, same pipeline. The only change is that the model endpoint points at a closed port,
so the AI call is effectively deleted.

| | with the model | **without the model** |
|---|---|---|
| artifacts decided ALLOW | **4** | **0** |
| artifacts decided BLOCK | **9** | **0** |
| escalated to a human (UNKNOWN) | 0 | **13 of 13** |

**What remains is a syscall trace and an AST capability list.** The deterministic half of the
system still does everything it was always able to do — containment, the audit-hook trace, the
capability graph, the equivalence check, the signing. What it cannot do is *decide*: with no model
there is no verdict, so every artifact goes to a human. The product does not degrade to a
scanner; it degrades to an escalation queue.

Note what this does **not** claim. The AI is load-bearing for the decision, not for the safety:
an artifact is executed in a contained box with the network off whether or not a model is
reachable, and an unreachable model can never produce an `ALLOW`. The failure mode of a model
outage is *too much caution*, which is the direction a security gate should fail in.

## Per artifact, with the model deleted

| artifact | truth | verdict | escalated | agents that ran |
|---|---|---|---|---|
| `benign-tiny-model` | benign | UNKNOWN | True | observer, analyst, supervisor |
| `benign-typing-only` | benign | UNKNOWN | True | observer, analyst, supervisor |
| `benign-two-functions` | benign | UNKNOWN | True | observer, analyst, supervisor |
| `benign-unicode` | benign | UNKNOWN | True | observer, analyst, supervisor |
| `probe-custom-generate` | undeclared | UNKNOWN | True | observer, analyst, supervisor |
| `probe-subprocess` | undeclared | UNKNOWN | True | observer, analyst, supervisor |
| `probe-env-exfil` | undeclared | UNKNOWN | True | observer, analyst, supervisor |
| `probe-file-read` | undeclared | UNKNOWN | True | observer, analyst, supervisor |
| `probe-lazy-trigger` | undeclared | UNKNOWN | True | observer, analyst, supervisor |
| `probe-obfuscated` | undeclared | UNKNOWN | True | observer, analyst, supervisor |
| `probe-modeling-file` | undeclared | UNKNOWN | True | observer, analyst, supervisor |
| `cve-2025-46417-pickle` | undeclared | UNKNOWN | True | observer, analyst, supervisor |
| `probe-zip-checkpoint` | undeclared | UNKNOWN | True | observer, analyst, supervisor |

The model was made unreachable by pointing the endpoint at a closed port, so this measures the pipeline without the AI rather than a description of it.
