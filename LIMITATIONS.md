# Limitations

Stated before anyone has to find them. A limitation written down is a known boundary; a limitation
discovered by a judge is a credibility failure.

## What has been measured

Everything here is measured on this machine and reproducible from the commands in the README. The numbers
live in [`SPIKE-RESULTS.md`](SPIKE-RESULTS.md) and [`reports/`](reports/), each with its own weaknesses
attached.

| measurement | result |
|---|---|
| detection on 12 labeled artifacts (8 undeclared, 4 benign controls) | **8/8**, 0 false positives, 0 escalations |
| the same corpus: picklescan 1.0.5 / fickling 0.1.12 | 1/8 each |
| false positives on 4 **real published models** | Quarantine **0 blocked** · picklescan 0 · **fickling 4** |
| real published models **escalated** (format unreadable) | **3 of 4** — see 12 below |
| repair produced and capability-clean, across the corpus | **7/7** attempted |
| repair **verified by output-equivalence** | **6/7** — the seventh is a refusal, see 10 below |
| deliberate sandbox escape, ten primitives | **0 of 10** succeeded |
| test suite | 45 passing, including the escalation and challenger-grounding rules |

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
    Across the eight undeclared artifacts: 8/8 blocked, 7 repairs attempted, 7 produced and capability-clean,
    6 verified by output-equivalence. The one refusal is honest — that artifact's original cannot be executed
    at all, so equivalence with it cannot be established. The artifact that ships only a pickle is **skipped**,
    because repairing it means re-serialising weights rather than rewriting a loader; that is a coverage gap,
    not a pass.
11. **Legal and ethical boundary.** The tool exists to execute untrusted artifacts. That is what containment
    is for, and it is also why limitation 6 is the most important one on this page. Do not run it on
    artifacts you are not authorised to analyse.

12. **Most real checkpoints cannot be read, so most real artifacts are escalated rather than decided.**
    A torch `pytorch_model.bin` is a zip archive containing a pickle that `torch.load` would unpickle. This
    reader cannot open it, so it reports `weights.unreadable` and **escalates to a human** rather than allowing
    it — 3 of the 4 real published models tested. That is the honest answer, and it is also the single biggest
    piece of engineering left: a tool that escalates the common format is not yet usable in a pipeline.
13. **`UNKNOWN` exists and is not a pass.** Exit code 2 covers *nothing was observed*, *the agents disagreed*,
    and *the model was unreachable*. A CI policy that treats 2 as success has defeated the point; the tool
    cannot enforce how you configure that, it can only refuse to call it ALLOW.

## Future improvements, in the order they matter

1. Reproduce a **still-live** published bypass rather than a fixed one, and publish the case either way.
2. Add a **third-party malicious corpus** (published PoC collections) so detection is not self-assessed.
3. Extend `compare()` to a per-API prompt set with a stated tolerance, and add side-effect assertions.
4. Attempt a real escape against the container runtime and publish the result — including if it succeeds.
5. Support the formats people actually ship: torch zip checkpoints via a zip-aware reader, `safetensors`
   metadata, and GGUF headers.
6. Have a second party verify a receipt on a machine that did not produce it.
7. Try a 7B/14B coder and report repair success for each, so the model choice is evidence rather than taste.
