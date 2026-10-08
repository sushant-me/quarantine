# Third-party negative controls

3 real, published model repositories. Every one is expected to be benign; any BLOCK here is a false positive.

| auditor | caught (of 0) | detection rate | false positives (of 3) | FP rate |
|---|---|---|---|---|
| **Quarantine (BLOCK)** | 0 | n/a | 0 | 0% |
| picklescan | 0 | n/a | 0 | 0% |
| fickling | 0 | n/a | 1 | 33% |

Escalated to a human (UNKNOWN): **0 of 3** — nothing observed, or the agents could not agree. Allowed: 3.

## Per artifact

| artifact | truth | category | incumbents | Quarantine | escalated | grounded | trace |
|---|---|---|---|---|---|---|---|
| `nepali-bert` | benign | real-published-model | fickling | **ALLOW** | False | True | 7 |
| `nepali-minilm-embedder` | benign | real-published-model | clean | **ALLOW** | False | True | 1 |
| `nepali-qwen-gguf` | benign | real-published-model | clean | **ALLOW** | False | True | 1 |

Labels are authored by us, so this measures the auditors against a known ground truth, not against the real world. See SPIKE-RESULTS.md. UNKNOWN is a third outcome, not a pass: it means nothing was observed or the agents could not agree, and it is referred to a human.
