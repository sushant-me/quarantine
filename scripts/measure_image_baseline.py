#!/usr/bin/env python3
"""Measure the noise floor of the analysis image.

    python scripts/measure_image_baseline.py

Imports the libraries the image ships, in the same container with the same flags, and
records what that alone produces. `quarantine/events.py::capability_events` subtracts those
events from every artifact trace.

Why this is measured rather than hand-listed: importing torch performs `ctypes.dlopen` of its
native libraries, sets and unsets `OPENBLAS_MAIN_FREE`, and creates its inductor cache. All
of that is real, and none of it is the artifact's doing. Guessing which of those to ignore
would be a denylist by another name, and it would drift with every torch release.
"""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from quarantine.events import baseline_path, noise_key   # noqa: E402
from quarantine.sandbox.execute import IMAGE, run_baseline  # noqa: E402

BASELINES = ROOT / "baselines"


def main() -> int:
    BASELINES.mkdir(exist_ok=True)
    work = BASELINES / "run"
    result = run_baseline(work)
    events = result["events"]

    path = baseline_path()
    with path.open("w", encoding="utf-8") as fh:
        for event in events:
            fh.write(json.dumps(event) + "\n")

    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    print(f"image          {IMAGE}")
    print(f"returncode     {result.get('returncode')}")
    print(f"events         {len(events)}")
    print(f"distinct keys  {len({noise_key(e['event'], e.get('detail', '')) for e in events})}")
    print(f"wrote          {path}  sha256={digest[:16]}")
    for event in events:
        print(f"   {event['event']:20} {str(event.get('detail'))[:70]}")
    print("\nAnything not listed here still counts as evidence. This is a floor, not a filter list.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
