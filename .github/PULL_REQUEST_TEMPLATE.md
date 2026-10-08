# What this change is

<!-- One or two sentences. If it fixes an issue, link it. -->

## The bar here is evidence, not plausibility

This is a security tool, so a change is judged by what it demonstrates. Please fill in whichever applies —
`CONTRIBUTING.md` explains why these are the questions.

- **Artifact that proves it** (a `corpus/` entry, or a minimal reproduction): <!-- path or description -->
- **Measurement that shows it** (before → after, and the command that produced it):
  ```
  .venv/bin/python scripts/eval_corpus.py
  ```
- **A rule or claim this change makes true or false**: <!-- which document says what, and did it change? -->

## If this adds a detection

- Which of the two failure modes does it close: *the payload did not act*, or *the code path never ran*?
  (See `LIMITATIONS.md`.)
- Does it produce a false positive on any of the 20 English controls or the Nepali/Indic set? Run
  `scripts/eval_corpus.py --dir corpus-real --label benign` — a detection that cries wolf on real models is
  not an improvement.

## Checks

- [ ] `scripts/check_eligibility.py` passes (do not weaken a check to make it pass — say so if you think one
      is wrong)
- [ ] `.venv/bin/python -m pytest -q` passes
- [ ] If a number in a document changed, every place that quotes it changed too — including
      `presentation/` and `docs/BUSINESS.md`
- [ ] If a check was added, it was **observed failing first**

## If a claim in the documents is now false

Say so here. A stale number in a submission is worse than a missing one, and this repository has caught that
class of drift more than once.
