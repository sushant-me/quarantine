# For the Nepal community

The challenge says it is *"about fostering the Nepali open source community"* and asks for *"something for the
Nepal community."* This is the honest version of that, rather than a paragraph of framing: the tool was
pointed at the models Nepali builders actually publish and download, and it found something.

## What was run

Three real, published Nepali-language repositories, fetched by [`scripts/fetch_nepali_models.py`](../scripts/fetch_nepali_models.py)
(the same third-party control method as `corpus-real/`), download counts as listed on the Hub on 2026-10-08:

| repository | by | downloads | format | Quarantine |
|---|---|---|---|---|
| [`Rajan/NepaliBERT`](https://huggingface.co/Rajan/NepaliBERT) | Rajan | 703 | `.bin` checkpoint | **ALLOW** |
| [`jangedoo/all-MiniLM-L6-v2-nepali`](https://huggingface.co/jangedoo/all-MiniLM-L6-v2-nepali) | jangedoo | 500 | `.safetensors` | **ALLOW** |
| [`mradermacher/Qwen-0.6b-nepali-instruct-GGUF`](https://huggingface.co/mradermacher/Qwen-0.6b-nepali-instruct-GGUF) | mradermacher | 368 | **`.gguf`** | **ALLOW** |

Result after the fix below: **0 blocked, 0 escalated, 3 allowed**. Full numbers in
[`reports/nepali-eval.md`](../reports/nepali-eval.md).

## The case that matters most: models that force `trust_remote_code=True`

Searching 268 Nepali/Indic repositories ([`scripts/find_remote_code_models.py`](../scripts/find_remote_code_models.py))
found **46 that ship `.py` files and 15 that declare `auto_map`** — repositories where using the model
*means running the author's Python on your machine*, by design. Two were added to the control set:

| repository | downloads | what it is | incumbents | Quarantine |
|---|---|---|---|---|
| [`ujjwal5454/nepali-voice-engine-v4`](https://huggingface.co/ujjwal5454/nepali-voice-engine-v4) | 740 | **Nepali** voice engine, custom architecture `NepaliVoiceEngine`, `auto_map` → `modeling_nepali_voice.py` | picklescan clean, fickling clean | **UNKNOWN — escalated** |
| [`prajdabre/rotary-indictrans2-en-indic-dist-200M`](https://huggingface.co/prajdabre/rotary-indictrans2-en-indic-dist-200M) | 1240 | IndicTrans2 (covers Nepali), custom architecture, **and** an 847 MB pickle checkpoint | picklescan clean | **UNKNOWN — escalated** |

**Neither picklescan nor fickling opens a `.py` file.** The code that would run on your machine is not in
their input set at all — this is the coverage hole, now demonstrated on real Nepali and Indic artifacts rather
than on our own corpus.

**And the honest part: we escalate both, because we cannot execute them.** Their custom code imports `torch`,
which is not in the analysis image, so the code path never runs — and a case where the code path never ran is
not one to approve *or* to block. The escalation says exactly that:

> `the artifact's shipped Python (modeling_nepali_voice.py) could not be executed (ModuleNotFoundError: No
> module named 'torch'), so the code path was never observed`

**That is the single highest-value next step**: ship an analysis image with `torch` (and the common modelling
dependencies) so custom architectures can be *executed and judged* rather than referred to a human. Two real
published models now motivate it, which is more than a roadmap bullet usually has.

### Two defects these two models found in our own tool

Running them exposed bugs that no fixture had:

1. **Partial observation was not escalated.** `rotary-indictrans2`'s weights loaded fine while its code path
   failed — so the case looked "observed", the supervisor did not escalate, and the analyst was left to
   interpret a `ModuleNotFoundError`. Fixed: if shipped Python exists and did not run, and no capability was
   observed, the case is escalated regardless of what else loaded.
2. **A `BLOCK` could be grounded by citing an *error*.** Every cited id existed, so the grounding check passed
   — and a benign published model was blocked on the strength of "this failed to import". Fixed: **a `BLOCK`
   must cite at least one capability event.** An error means we could not look; it is not an observed
   capability. The rule now lives in `semantic/analyst.py::verdict_is_grounded` and has its own tests.

After both fixes: **0 false positives** across the five Nepali/Indic models, and detection on the labeled
corpus unchanged at 9/9.

## What pointing the tool at Nepal actually found

The first run **escalated the GGUF model** — the tool reported *"no custom code and no weight files found"* and
sent it to a human. The reason is the shape of this ecosystem:

> Of the thirty most-downloaded Nepali models on the Hub, **six are GGUF quantisations** — and the
> quantisation publisher alone (`mradermacher`) republishes Nepali fine-tunes of Qwen, MiniCPM, Llama and
> others. GGUF is the format Nepali users actually download, because it is what runs on a laptop.

Our reader knew `pytorch_model.bin` and `safetensors` and treated everything else as "nothing to see". A
sample of the ecosystem showed that the *dominant* format was the one we could not read. That is now fixed:
GGUF is **validated and not executed**, exactly like safetensors, because it contains no pickle and no
callable — and a pickle renamed `.gguf` fails the magic check and is escalated rather than trusted
(`sandbox_runner.py::load_gguf`, tests included).

This is the clearest example we have of why third-party artifacts matter: no amount of reasoning about our own
corpus would have produced it. It took downloading what real Nepali users download.

## What a Nepali developer gets

```bash
git clone <this repo> && cd quarantine
./scripts/serve_model.sh                       # local open-weight model, no API key
python -m quarantine.cli inspect ~/.cache/huggingface/hub/models--Rajan--NepaliBERT
```

Exit codes are the integration point: **0 allow · 1 block · 2 escalate-to-a-human.** In CI, a `BLOCK` fails
the job and the signed receipt records what was observed, which model judged it, and what the repair did.

## What this is not, yet

- **Three models is a start, not a survey.** We have not measured the whole Nepali ecosystem. What we can say
  is what we ran, on the day we ran it, with the numbers above.
- **We did not find a Nepali model shipping custom `modeling_*.py`** — the highest-risk case, because it
  forces users into `trust_remote_code=True`, i.e. running unvetted code by design. Absence of evidence here
  is partly a function of sample size, and finding one would be the most useful next contribution.
- **`safetensors` and GGUF are validated, not inspected for poisoned values.** A backdoored Nepali model with
  a clean container is out of scope for this tool ([`LIMITATIONS.md`](../LIMITATIONS.md) item 15).
- **The labels, the corpus and the detections are ours.** The Nepali models above are genuinely third-party;
  the malicious cases are ours by construction, with hostnames under `.invalid`.

## An invitation

The most useful contribution to this project from Nepal is **an artifact, not a patch**: a Nepali model that
behaves in a way its own README does not declare, or a Nepali repository that ships custom code. It becomes a
labelled case with a benign counterpart, and the corpus gets more honest as it grows. See
[`CONTRIBUTING.md`](../CONTRIBUTING.md) — and if you find something that looks live, [`SECURITY.md`](../SECURITY.md)
first.
