#!/usr/bin/env python3
"""Attempt a sandbox escape, deliberately, and write down what held.

A containment claim that has never been attacked is a claim, not a measurement.
This runs ten breakout primitives in exactly the container configuration the
artifacts get, and reports which ones succeeded — success is a finding, not a bug
to be hidden.

    python scripts/escape_attempt.py
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from quarantine.sandbox.execute import IMAGE, run_escape  # noqa: E402

REPORTS = ROOT / "reports"


def main() -> int:
    REPORTS.mkdir(exist_ok=True)
    workdir = REPORTS / "escape-run"
    result = run_escape(workdir)

    probes = result.get("probes", [])
    escaped = result.get("escaped", [])
    lines = [
        "# Sandbox escape attempt",
        "",
        f"Image `{IMAGE}` · container config: `--network none --read-only --cap-drop ALL "
        "--security-opt no-new-privileges --user <invoking uid> --pids-limit 128 "
        "--memory 512m --cpus 1`.",
        "",
        f"**Result: {len(escaped)} of {len(probes)} breakout primitives succeeded.**",
        "",
        "| probe | primitive | outcome | detail |",
        "|---|---|---|---|",
    ]
    for p in probes:
        outcome = "**ESCAPED**" if p["succeeded"] else "blocked"
        lines.append(f"| `{p['probe']}` | {p['primitive']} | {outcome} | `{p['detail'][:110]}` |")
    lines += [
        "",
        "## Reading this table",
        "",
        "- `blocked` rows are the containment working. The `detail` column names the mechanism "
        "(an errno, a missing file, a namespace boundary) — not a promise.",
        "- **Any `ESCAPED` row is a real finding** and must be reported as one before this tool is "
        "claimed to be safe for untrusted artifacts.",
        "- These are ten well-known primitives, not a fuzzing campaign. A clean table means "
        "*these ten* failed; it does not mean the box cannot be broken.",
        "",
        f"Identity inside the box: `{json.dumps(result.get('identity', {}))}`",
        "",
    ]
    (REPORTS / "sandbox-escape.md").write_text("\n".join(lines), encoding="utf-8")
    (REPORTS / "sandbox-escape.json").write_text(json.dumps(result, indent=2), encoding="utf-8")

    print("\n".join(lines[:12]))
    print(f"\nwrote {REPORTS / 'sandbox-escape.md'}")
    return 0 if not escaped else 1


if __name__ == "__main__":
    raise SystemExit(main())
