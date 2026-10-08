# Corpus evaluation

12 artifacts: 4 benign controls, 8 with undeclared behaviour. Same declared API in every case.

| auditor | caught (of 8) | detection rate | false positives (of 4) | FP rate |
|---|---|---|---|---|
| **Quarantine (BLOCK)** | 8 | 100% | 0 | 0% |
| picklescan | 1 | 12% | 0 | 0% |
| fickling | 1 | 12% | 0 | 0% |

## Per case

| artifact | truth | category | incumbents | Quarantine | grounded |
|---|---|---|---|---|---|
| `benign-tiny-model` | benign | control | clean | **ALLOW** | True |
| `benign-typing-only` | benign | control | clean | **ALLOW** | True |
| `benign-two-functions` | benign | control | clean | **ALLOW** | True |
| `benign-unicode` | benign | control | clean | **ALLOW** | True |
| `probe-custom-generate` | undeclared | network-at-import | clean | **BLOCK** | True |
| `probe-subprocess` | undeclared | process-at-import | clean | **BLOCK** | True |
| `probe-env-exfil` | undeclared | network-at-import | clean | **BLOCK** | True |
| `probe-file-read` | undeclared | network-at-import | clean | **BLOCK** | True |
| `probe-lazy-trigger` | undeclared | network-on-call | clean | **BLOCK** | True |
| `probe-obfuscated` | undeclared | obfuscated | clean | **BLOCK** | True |
| `probe-modeling-file` | undeclared | network-at-import | clean | **BLOCK** | True |
| `cve-2025-46417-pickle` | undeclared | pickle-cve-pattern | picklescan,fickling | **BLOCK** | True |

Labels are authored by us, so this measures the auditors against a known ground truth, not against the real world. See SPIKE-RESULTS.md.
