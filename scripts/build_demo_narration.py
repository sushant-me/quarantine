#!/usr/bin/env python3
"""Generate the demo video's narration as a timed subtitle file.

The video is silent on purpose: there is no English text-to-speech on this machine, and a
synthetic voice would be worse than none. What it needs is a human reading a script, so this
produces one that is **in sync by construction** — the cue timings are derived from the same
scene list the video was built from, read back out of `reports/video/transcript.txt`.

    python scripts/build_demo_narration.py

Writes presentation/quarantine-demo-narration.srt (and prints it).
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TRANSCRIPT = ROOT / "reports" / "video" / "transcript.txt"
OUT = ROOT / "presentation" / "quarantine-demo-narration.srt"

SCENE_LINE = re.compile(r"^=== (\S+)\s+\((\d+)s\)\s+(.+)$")

# One cue per scene. Kept to a comfortable speaking pace for the scene's length — roughly
# two and a half words a second — so reading along does not drift out of sync.
NARRATION = {
    "01-title": "Every model you download is code you did not write. This is Quarantine — "
                "an offline clean room that runs it where it cannot hurt you.",
    "02-scanner": "First, the scanner everyone already runs. Picklescan reports zero infected files and zero "
                  "suspicious globals. It is clean, and it is wrong.",
    "03-gap": "That is the gap. Neither picklescan nor fickling ever opens a Python file, and seven of our "
              "nine malicious artifacts hide in exactly those files.",
    "04a-trace": "So we execute it inside Docker, with the network off, a read-only root, every capability "
                 "dropped, and an audit hook recording every sensitive operation.",
    "04b-trace": "The artifact runs, and the trace shows what it did: a file read outside its own directory, "
                 "and a DNS lookup to an address that cannot resolve.",
    "04c-trace": "This is behaviour, not a signature. The artifact cannot rename its way out of it, and the "
                 "trace is the evidence everything downstream reasons over.",
    "05-verdict": "Then an agent team reads it. The analyst decides and cites trace ids. The challenger tries "
                  "to refute it. The repairer rewrites the offending function, and a verifier proves it.",
    "05b-escalate": "And when we cannot look, we escalate. This artifact could not be executed, so its code "
                    "path was never observed: UNKNOWN, exit code two, a human decides.",
    "06c-their-corpus": "We also ran picklescan's own malicious corpus — ninety-one samples, one per real "
                        "advisory. They flag eighty-eight; we observe forty-three. They win there, and we say "
                        "so. This is the other half of the pair, not a replacement.",
    "06b-nepal": "Then we pointed it at Nepal: two hundred and sixty-eight repositories, forty-six shipping "
                 "Python, fifteen requiring remote code. That search found a bug in our own tool.",
    "06-numbers": "The measured numbers. Nine of nine on our labeled corpus, against two of nine for each "
                  "incumbent. Zero false positives on twenty real published models, where fickling flags "
                  "eighteen.",
    "06b-repair": "The repair is proven, not asserted — identical outputs on twelve prompts and zero capability "
                  "operations, measured from the trace. Six of seven verified, and the seventh is a refusal we "
                  "state plainly.",
    "07-containment": "We attacked our own box: ten breakout primitives, including host mounts and runtime "
                      "sockets. Zero succeeded. That is a measurement, not a guarantee.",
    "08-limits": "And here is what we do not claim. No scanner bypass, no proof the box cannot be broken, "
                 "poisoned weights out of scope, and the corpus is ours.",
    "09-end": "Quarantine. Apache two. No API key, no egress, and receipts you can verify with openssl. "
              "Thank you.",
}


def _stamp(seconds: float) -> str:
    ms = int(round(seconds * 1000))
    h, ms = divmod(ms, 3_600_000)
    m, ms = divmod(ms, 60_000)
    s, ms = divmod(ms, 1000)
    return f"{h:02d}:{m:02d}:{s:02d},{ms:03d}"


def main() -> int:
    if not TRANSCRIPT.exists():
        print(f"missing {TRANSCRIPT} — build the video first", file=sys.stderr)
        return 2

    scenes = []
    for line in TRANSCRIPT.read_text(encoding="utf-8").splitlines():
        match = SCENE_LINE.match(line)
        if match:
            scenes.append((match.group(1), int(match.group(2)), match.group(3)))
    if not scenes:
        print("no scenes found in the transcript", file=sys.stderr)
        return 2

    missing = [name for name, _, _ in scenes if name not in NARRATION]
    if missing:
        print(f"narration missing for: {missing}", file=sys.stderr)
        return 2

    blocks, t = [], 0.0
    for index, (name, duration, title) in enumerate(scenes, start=1):
        start, end = t, t + duration
        t = end
        blocks.append(f"{index}\n{_stamp(start)} --> {_stamp(end)}\n{NARRATION[name]}\n")
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text("\n".join(blocks), encoding="utf-8")

    print(f"wrote {OUT}  ({len(blocks)} cues, {t:.0f}s)")
    print("\n".join(blocks))
    return 0


if __name__ == "__main__":
    sys.exit(main())
