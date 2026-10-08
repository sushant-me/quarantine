# Corpus evaluation

13 artifacts: 4 benign controls, 9 with undeclared behaviour. Same declared API in every case.

| auditor | caught (of 9) | detection rate | false positives (of 4) | FP rate |
|---|---|---|---|---|
| **Quarantine (BLOCK)** | 9 | 100% | 0 | 0% |
| picklescan | 2 | 22% | 0 | 0% |
| fickling | 2 | 22% | 0 | 0% |

Escalated to a human (UNKNOWN): **0 of 13** — nothing observed, or the agents could not agree. Allowed: 4.

## Per artifact

| artifact | truth | category | incumbents | Quarantine | escalated | grounded | trace |
|---|---|---|---|---|---|---|---|
| `benign-tiny-model` | benign | control | clean | **ALLOW** | False | True | 0 |
| `benign-typing-only` | benign | control | clean | **ALLOW** | False | True | 0 |
| `benign-two-functions` | benign | control | clean | **ALLOW** | False | True | 0 |
| `benign-unicode` | benign | control | clean | **ALLOW** | False | True | 0 |
| `probe-custom-generate` | undeclared | network-at-import | clean | **BLOCK** | False | True | 3 |
| `probe-subprocess` | undeclared | process-at-import | clean | **BLOCK** | False | True | 2 |
| `probe-env-exfil` | undeclared | network-at-import | clean | **BLOCK** | False | True | 2 |
| `probe-file-read` | undeclared | network-at-import | clean | **BLOCK** | False | True | 3 |
| `probe-lazy-trigger` | undeclared | network-on-call | clean | **BLOCK** | False | True | 2 |
| `probe-obfuscated` | undeclared | obfuscated | clean | **BLOCK** | False | True | 4 |
| `probe-modeling-file` | undeclared | network-at-import | clean | **BLOCK** | False | True | 3 |
| `cve-2025-46417-pickle` | undeclared | pickle-cve-pattern | picklescan,fickling | **BLOCK** | False | True | 6 |
| `probe-zip-checkpoint` | undeclared | zip-checkpoint | picklescan,fickling | **BLOCK** | False | True | 6 |

Labels are authored by us, so this measures the auditors against a known ground truth, not against the real world. See SPIKE-RESULTS.md. UNKNOWN is a third outcome, not a pass: it means nothing was observed or the agents could not agree, and it is referred to a human.
