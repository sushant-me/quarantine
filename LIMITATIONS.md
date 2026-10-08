# Limitations

Stated before anyone has to find them. A limitation written down is a known boundary; a limitation
discovered by a judge is a credibility failure.

## What has been measured

Everything here is measured on this machine and reproducible from the commands in the README. The numbers
live in [`SPIKE-RESULTS.md`](SPIKE-RESULTS.md) and [`reports/`](reports/), each with its own weaknesses
attached.

| measurement | result |
|---|---|
| detection on 13 labeled artifacts (9 undeclared, 4 benign controls) | **9/9**, 0 false positives, 0 escalations |
| the same corpus: picklescan 1.0.5 / fickling 0.1.12 | **2/9** each (22%) |
| false positives on **20 real published models** | Quarantine **0 blocked** · picklescan **0** · **fickling 18 (90%)** |
| real published models **escalated** | **0 of 20** — the reader opens torch's zip format *and* validates safetensors |
| repair produced and capability-clean, across the corpus | **7/7** attempted (2 of 9 ship only weights) |
| repair **verified by output-equivalence** | **6/7** — the seventh is a refusal, see 10 below |
| deliberate sandbox escape, ten primitives | **0 of 10** succeeded |
| scanner denylist coverage (19 direct I/O primitives, 6 benign controls) | Quarantine **19/19 observed, 0/6 false positives** · picklescan verdict **10/19** · fickling flagged **25/25 — operations *and* controls** |
| test suite | 58 passing, including the escalation, challenger-grounding and reader rules |

## What is NOT established

1. **The malicious corpus is ours.** Eight undeclared artifacts were written by us against a declared API we
   also wrote. Detection on self-authored payloads is weak evidence. Four real, published models cover the
   *negative* side, but there is **no third-party corpus of malicious artifacts** here.
2. **The third-party controls are tiny models.** `bert-tiny`, `tiny-gpt2`, `tiny-random-bert`,
   `tiny-random-gpt2` are real repositories and none ships custom Python. Production artifacts have more
   moving parts.
3. **No public CVE is reproduced as a live bypass.** The pickle case reproduces the *pattern* of
   [GHSA-93mv-x874-956g](https://osv.dev/vulnerability/GHSA-93mv-x874-956g), and **current picklescan catches
   it**. The advantage claimed here is the **code path no scanner reads** (`custom_generate/`,
   `modeling_*.py`), not a pickle bypass.
4. **One model size.** Only `qwen2.5-coder-3b-instruct-q4_k_m`. A 1.5B general model failed the repair task;
   7B and larger are untried.
5. **Equivalence is 12 prompts plus a capability check, not a proof.** `compare()` runs twelve inputs —
   case, punctuation, unicode, empty, whitespace, a tab, digits, a newline, a 300-character string — and
   additionally requires that the repaired loader performed **no capability operation** in the trace. That is
   far stronger than the three-prompt smoke test it replaced, but it is still not a proof of behavioural
   equivalence: side effects that produce no output are invisible to it, and twelve prompts are not a
   specification.
6. **The escape attempt is ten primitives, not a fuzzing campaign.** A clean table means *those ten* failed.
   No kernel exploit, no container-runtime CVE, and no race was attempted. It is not a claim that the box
   cannot be broken.
7. **No independent receipt verification.** The receipt is verified by our own verifier with our own key.
   It uses standard primitives (Ed25519 over canonical JSON, DSSE-shaped envelope) and is **not audited**.
8. **Python only, and zip-format checkpoints are not executed.** A real `pytorch_model.bin` is a zip archive;
   the plain-pickle reader reports `weights.unreadable` and moves on — recorded honestly, and deliberately
   **not** treated as evidence of anything. `safetensors` is not attempted at all. ONNX custom ops, GGUF
   metadata and C/Rust extensions are untouched.
9. **The repair removes capability; it does not prove absence.** `forbidden_in_source` is an AST check. An
   obfuscated capability it cannot see would pass. It raises the floor.
10. **The repair is verified on 6 of 7 attempts, and it is not attempted for weight-only payloads.**
    Across the nine undeclared artifacts: 9/9 blocked, 7 repairs attempted (two ship only a weight file),
    6 verified by output-equivalence. The one refusal is honest — that artifact's original cannot be executed
    at all, so equivalence with it cannot be established. The artifact that ships only a pickle is **skipped**,
    because repairing it means re-serialising weights rather than rewriting a loader; that is a coverage gap,
    not a pass.
11. **Legal and ethical boundary.** The tool exists to execute untrusted artifacts. That is what containment
    is for, and it is also why limitation 6 is the most important one on this page. Do not run it on
    artifacts you are not authorised to analyse.

12. **The reader now opens torch zip checkpoints, but it stubs the tensor machinery to do so.** It reads
    `archive/data.pkl` and unpickles it, which is where the code execution lives — so the security question is
    answered faithfully, and real models no longer escalate. But `torch._utils._rebuild_tensor_v2`, the
    `*Storage` types and numpy's array reconstruction cannot be imported without torch, so they are stubbed and
    the **tensor values are not reconstructed**. A payload that hid its behaviour inside a tensor rebuild helper
    would not be reproduced. The line is drawn deliberately: **nothing that can reach the network or the
    filesystem is stubbed**, and `builtins.eval/exec/open/__import__` are excluded explicitly.
13. **`UNKNOWN` exists and is not a pass.** Exit code 2 covers *nothing was observed*, *the agents disagreed*,
    and *the model was unreachable*. A CI policy that treats 2 as success has defeated the point; the tool
    cannot enforce how you configure that, it can only refuse to call it ALLOW.


14. **No scanner bypass is claimed, and we tried to find one.** We built 19 one-pickle probes for
    standard-library callables that perform network, filesystem, process or dynamic-code operations
    and looked for one that both incumbents miss. **Fickling flagged all 25 probes including the six
    benign controls, so no such gap exists in this set** — a negative result, published in
    `reports/scanner-coverage.md`. picklescan's *verdict* misses 9 of the 19 while calling
    `os.getcwd` and `datetime.now` infected, so its denylist is misaligned in both directions; but
    "misaligned denylist" is not "undetectable attack", and the product does not rest on it. The
    measured difference is coverage of the code path.

15. **`safetensors` and `gguf` are validated, not inspected — and that is a different threat model.** We check the
    container (header length, JSON index, tensor descriptors), which is enough to conclude that no code
    can execute from it: the format has no pickle and no callable. It says nothing about the *values*.
    **A poisoned-weights or backdoored-model attack is out of scope for this tool** and would need
    detection research of a completely different kind. A file that merely claims the suffix but is not a
    valid container is rejected into the escalation path rather than trusted. The same applies to GGUF
    (item added after the Nepali control set showed GGUF is that ecosystem's dominant distribution format).
16. **The Nepali evidence is three models, not a survey.** They are real and third-party, but small in number:
    we can state what we ran on 2026-10-08, not what the whole Nepali ecosystem contains. We also did not find
    a Nepali model shipping custom `modeling_*.py`, which would be the highest-risk case.

17. **Custom model code that needs a modelling framework escalates by default, and the image that fixes
    it measures worse.** `docker/Dockerfile.analysis` (CPU torch + transformers, 362 MB) exists and works,
    but on the Nepali/Indic controls it *raised* false positives from 0 to 2 of 5, and it broke legacy
    `pytorch_model.bin` reading that the stubs had handled. It is therefore opt-in via
    `QUARANTINE_IMAGE=quarantine-analysis:latest`, with the measurements behind that decision in
    [`SPIKE-RESULTS.md`](SPIKE-RESULTS.md) §3b. Proper event attribution is what would make it the default.
18. **Behaviour-based detection is weak against payloads that cannot fire in isolation — measured, not
    suspected.** On picklescan's own corpus (91 malicious samples with real GHSA provenance) our contained run
    observed the payload act on **43 (47%)**, while their denylist flagged **88 (97%)**. Their payloads typically
    name a vulnerable entry point in a host library (`cProfile.run`, `pty.spawn`,
    `torch.utils.collect_env.run`) and do nothing when loaded alone. This is not a defect to be fixed by better
    engineering; it is the boundary of the approach, and it is why the honest positioning is *use both* rather
    than *replace*. Our advantage is confined to the thing it was built for: the custom Python every scanner
    ignores, and the repair none of them attempt.

19. **The analyst's citation is occasionally non-compliant, and the fail-safe then escalates a decidable
    case.** A 3B model sometimes answers `BLOCK` while citing an id that is not a capability event; the
    grounding rule correctly refuses it. During one measurement round this moved the corpus from 9/9 to 8/9
    with 1 escalation, and a re-run with a third attempt allowed and sharper feedback returned it to 9/9. So
    the number carries real run-to-run variance, and the honest way to state it is *9/9 on the run recorded
    in `reports/corpus-eval.json`*, not *always 9/9*. The fail-safe direction is right — an ungrounded block is
    never accepted — but the variance is a property of the model, not of the rule.

## Future improvements, in the order they matter

1. Reproduce a **still-live** published bypass rather than a fixed one, and publish the case either way.
2. Add a **third-party malicious corpus** (published PoC collections) so detection is not self-assessed.
3. Extend `compare()` to a per-API prompt set with a stated tolerance, and add side-effect assertions.
4. Attempt a real escape against the container runtime and publish the result — including if it succeeds.
5. Support the formats people actually ship: torch zip checkpoints via a zip-aware reader, `safetensors`
   metadata, and GGUF headers.
6. Have a second party verify a receipt on a machine that did not produce it.
7. Try a 7B/14B coder and report repair success for each, so the model choice is evidence rather than taste.
