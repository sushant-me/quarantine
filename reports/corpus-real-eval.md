# Third-party negative controls

4 real, published model repositories. Every one is expected to be benign; any BLOCK here is a false positive.

| auditor | caught (of 0) | detection rate | false positives (of 4) | FP rate |
|---|---|---|---|---|
| **Quarantine (BLOCK)** | 0 | n/a | 0 | 0% |
| picklescan | 0 | n/a | 0 | 0% |
| fickling | 0 | n/a | 4 | 100% |

## Per artifact

| artifact | truth | category | incumbents | Quarantine | grounded | trace |
|---|---|---|---|---|---|---|
| `bert-tiny` | benign | real-published-model | fickling | **ALLOW** | True | 1 |
| `tiny-gpt2` | benign | real-published-model | fickling | **ALLOW** | True | 0 |
| `tiny-random-bert` | benign | real-published-model | fickling | **ALLOW** | True | 1 |
| `tiny-random-gpt2` | benign | real-published-model | fickling | **ALLOW** | True | 1 |

Labels are authored by us, so this measures the auditors against a known ground truth, not against the real world. See SPIKE-RESULTS.md.
