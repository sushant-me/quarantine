# Repair evaluation

All 9 artifacts with undeclared behaviour, run end to end. Every number is read back from the signed receipt, so this measures what the product emits.

| measure | result |
|---|---|
| blocked by the local model (grounded) | 9/9 (100%) |
| repair attempted (needs a grounded BLOCK) | 7/9 (78%) |
| repair produced and passed the capability gate | 7/7 (100%) |
| repair **verified by output-equivalence** | 6/7 (86%) |

## Per artifact

| artifact | category | custom code | verdict | repair ok | equivalent | prompts | caps orig → repaired |
|---|---|---|---|---|---|---|---|
| `probe-custom-generate` | network-at-import | yes | BLOCK | True | True | 12 | 2 → 0 |
| `probe-subprocess` | process-at-import | yes | BLOCK | True | True | 12 | 1 → 0 |
| `probe-env-exfil` | network-at-import | yes | BLOCK | True | True | 12 | 1 → 0 |
| `probe-file-read` | network-at-import | yes | BLOCK | True | True | 12 | 2 → 0 |
| `probe-lazy-trigger` | network-on-call | yes | BLOCK | True | True | 12 | 1 → 0 |
| `probe-obfuscated` | obfuscated | yes | BLOCK | True | False | 12 | 1 → 0 |
| `probe-modeling-file` | network-at-import | yes | BLOCK | True | True | 12 | 2 → 0 |
| `cve-2025-46417-pickle` | pickle-cve-pattern | no | BLOCK | False | False | None | 0 → 0 |
| `probe-zip-checkpoint` | zip-checkpoint | no | BLOCK | False | False | None | 0 → 0 |

Repair is only attempted when the verdict is a grounded BLOCK, and an artifact whose payload is a pickle ships no custom code to repair.
