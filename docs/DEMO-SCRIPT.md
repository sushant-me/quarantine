# Demo script — 3 minutes, network off

**Deliverable:** the required demo video. **Format:** 3:00 max, 1920×1080, no music, no cuts to slides —
every frame is the real tool running on this machine with the network off.

The rule for the whole video: **show, then say.** If a claim cannot be shown in the frame, it does not go in
the narration.

---

## Pre-flight (do this five minutes before recording)

```bash
./scripts/serve_model.sh &                       # wait for /health to return ok
docker image ls python:3.12-slim                 # must be present, no pull on camera
PYTHONPATH=src .venv/bin/python -m pytest -q     # 30 passed
rm -rf runs/demo                                 # start clean
```

Turn the Wi-Fi off **on camera** at the start and leave it off. `curl -s -o /dev/null -w '%{http_code}'
http://127.0.0.1:8081/health` should still print `200` — the model is local, which is the point.

---

## Shot list

### 00:00–00:20 · The problem, with a number

**On screen:** a terminal, and this command's output scrolling:

```bash
.venv/bin/python -m picklescan --path corpus/probe-custom-generate
```

> "This artifact declares a pure text transform. Twenty-two thousand people download models like it a day.
> This is what your security team runs before they trust one — and it says **clean**."

**Do not cut away from `Scanned files: 1 · Infected files: 0`.** The number `1` is the whole story: the only
file it looked at is the weights. The Python that runs on load is not in its input set.

### 00:20–00:35 · Name the inversion

**On camera, in one breath:**

> "In 2026, hundreds of malicious models and agent skills were found on Hugging Face and ClawHub. A published
> proof-of-concept got past picklescan while reading `/etc/passwd` and exfiltrating it over DNS. The industry's
> answer is a *signature* — and a signature tells you who published the bytes, not what they do.
> **So we measure what they do.**"

### 00:35–01:15 · Run it — the artifact executes where it cannot hurt you

```bash
PYTHONPATH=src .venv/bin/python -m quarantine.cli inspect corpus/probe-custom-generate --out runs/demo
```

**Narrate the trace as it prints, not before:**

> "Container, no network, read-only filesystem, every capability dropped, running as me — not root.
> And the artifact does this: it reads `/etc/hostname` — a file outside itself — and puts it into a DNS query
> for a hostname that cannot exist. **That is the behaviour the scanner never saw.**"

### 01:15–01:45 · The model reads it

**On screen:** the verdict line, then the receipt.

```bash
.venv/bin/python -c "import json;print(json.load(open('runs/demo/verdict.json'))['verdict'])"
```

> "A local open-weight model — three billion parameters, on this laptop, no API key, no account — reads the
> declared behaviour against what actually happened. Verdict: **BLOCK**. And it has to cite trace ids that
> really exist; an answer that invents evidence is thrown out and retried."

Point at `cited_ids: [5, 6]` on screen.

### 01:45–02:15 · Repair, and the proof that it is real

**On screen:** `runs/demo/loader_sanitized.py` (four lines), then the equivalence result.

> "It also writes the repair — the function bodies only; the harness writes the boilerplate. Then the boring
> part that makes it trustworthy: the original and the repaired loader are both executed, in the same box, on
> the same prompts. Identical outputs, or the repair is rejected no matter how good it looked."

### 02:15–02:40 · The receipts, and the honest numbers

**Verify it without trusting us** — `tools/verify_receipt_standalone.py` is stdlib-only, checks the
Ed25519 signature with `openssl` (a different implementation than the one that signed it), and the public key
is committed. Flip the verdict in the JSON and it says NOT VERIFIED; that is the beat.

```bash
PYTHONPATH=src .venv/bin/python scripts/eval_corpus.py --prefix demo 2>&1 | tail -8
```

> "Twelve artifacts, the same declared API in every one. We catch eight of eight. Both scanners that everyone
> already runs catch one of eight — because seven of the eight payloads live in files they never open.
> And on four **real published models**, we raise zero false positives, while one widely used scanner flags
> all four, because a real checkpoint is a zip archive it cannot parse."

### 02:40–03:00 · Say the limits out loud, then stop

**On screen:** `LIMITATIONS.md`, scrolled to the top.

> "The malicious corpus and its labels are ours — that is weak evidence and we say so. One model size.
> Equivalence is a three-prompt smoke test. We attacked our own sandbox with ten breakout primitives and none
> succeeded — which is not the same as proving it cannot be broken.
> **Behaviour is the only ground truth about what a model artifact does. We measure it, we gate on it, and we
> sign what we saw.** Apache-2.0. Offline. Run it yourself."

---

## What must NOT be said

| Never say | Why |
|---|---|
| "we bypass picklescan" | current picklescan **catches** our pickle pattern. The claim is the code path, not a bypass |
| "we detect all malware" | 9/9 on a corpus we wrote is not a detection rate for the world |
| "the sandbox is secure" | ten primitives failed; nobody has fuzzed it |
| "AI-powered" as a phrase | point at the file and function that consumes the output instead |
| any number not on screen | every number in this script is in `SPIKE-RESULTS.md` with its weakness attached |

---

## If something breaks on camera

- **Model server down:** the CLI prints `reachable=False` and returns `UNKNOWN`. Say so, restart it, and keep
  the take — an honest `UNKNOWN` is a better advertisement than a silent wrong answer.
- **Docker missing:** the behavioural pass reports `docker not found` and the run degrades to static only.
  Do not record in that state; the demo *is* the execution.
- **Slow model:** the 3B model takes 10–15 s per verdict. Let it be slow on camera. Fast and fake is worse.

## Post-production

Cut nothing that shows a limitation. The two beats that win the room are the scanner saying **clean** and the
trace showing what it missed; everything else is evidence that the first two are real.
