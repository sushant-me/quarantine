# Third-party negative controls

20 real, published model repositories. Every one is expected to be benign; any BLOCK here is a false positive.

| auditor | caught (of 0) | detection rate | false positives (of 20) | FP rate |
|---|---|---|---|---|
| **Quarantine (BLOCK)** | 0 | n/a | 0 | 0% |
| picklescan | 0 | n/a | 0 | 0% |
| fickling | 0 | n/a | 18 | 90% |

Escalated to a human (UNKNOWN): **0 of 20** — nothing observed, or the agents could not agree. Allowed: 20.

## Per artifact

| artifact | truth | category | incumbents | Quarantine | escalated | grounded | trace |
|---|---|---|---|---|---|---|---|
| `bert-tiny` | benign | real-published-model | fickling | **ALLOW** | False | True | 7 |
| `google-bert-tiny-real` | benign | real-published-model | fickling | **ALLOW** | False | True | 1 |
| `tiny-distilbert-cased` | benign | real-published-model | fickling | **ALLOW** | False | True | 0 |
| `tiny-gpt2` | benign | real-published-model | fickling | **ALLOW** | False | True | 0 |
| `tiny-random-bart` | benign | real-published-model | fickling | **ALLOW** | False | True | 5 |
| `tiny-random-bert` | benign | real-published-model | fickling | **ALLOW** | False | True | 8 |
| `tiny-random-clip` | benign | real-published-model | fickling | **ALLOW** | False | True | 7 |
| `tiny-random-distilbert` | benign | real-published-model | fickling | **ALLOW** | False | True | 5 |
| `tiny-random-electra` | benign | real-published-model | fickling | **ALLOW** | False | True | 7 |
| `tiny-random-gpt-neo` | benign | real-published-model | fickling | **ALLOW** | False | True | 8 |
| `tiny-random-gpt2` | benign | real-published-model | fickling | **ALLOW** | False | True | 8 |
| `tiny-random-llama` | benign | real-published-model | clean | **ALLOW** | False | True | 1 |
| `tiny-random-mistral` | benign | real-published-model | fickling | **ALLOW** | False | True | 5 |
| `tiny-random-opt` | benign | real-published-model | fickling | **ALLOW** | False | True | 6 |
| `tiny-random-phi` | benign | real-published-model | clean | **ALLOW** | False | True | 1 |
| `tiny-random-roberta` | benign | real-published-model | fickling | **ALLOW** | False | True | 7 |
| `tiny-random-t5` | benign | real-published-model | fickling | **ALLOW** | False | True | 5 |
| `tiny-random-vit` | benign | real-published-model | fickling | **ALLOW** | False | True | 5 |
| `tiny-random-wav2vec2` | benign | real-published-model | fickling | **ALLOW** | False | True | 6 |
| `tiny-random-whisper` | benign | real-published-model | fickling | **ALLOW** | False | True | 5 |

Labels are authored by us, so this measures the auditors against a known ground truth, not against the real world. See SPIKE-RESULTS.md. UNKNOWN is a third outcome, not a pass: it means nothing was observed or the agents could not agree, and it is referred to a human.
