#!/usr/bin/env python3
"""Evaluate the repair path across the whole corpus, not one artifact.

For every artifact with undeclared behaviour: run the full loop (static → contained
execution → local-model verdict → repair → equivalence), read the signed receipt back,
and report how often a model-written repair was produced and *verified*.

Reading the receipt rather than re-implementing the loop is deliberate: it means this
measures exactly what the product emits, not a parallel code path that could drift.

    python scripts/eval_repair.py

Writes reports/repair-eval.json and reports/repair-eval.md.
"""

from __future__ import annotations

import base64
import json
import shutil
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REPORTS = ROOT / "reports"


def inspect(name: str) -> dict:
    out = REPORTS / "repair-runs" / name
    if out.exists():
        shutil.rmtree(out)
    cmd = ["env", f"PYTHONPATH={ROOT / 'src'}", str(ROOT / ".venv" / "bin" / "python"),
           "-m", "quarantine.cli", "inspect", f"corpus/{name}", "--out", str(out)]
    proc = subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True, timeout=1800)
    row: dict = {"cli_rc": proc.returncode, "has_receipt": False}
    receipt = out / "receipt.json"
    if receipt.exists():
        payload = json.loads(base64.b64decode(json.loads(receipt.read_text())["payload"]))
        eq = payload.get("equivalence") or {}
        row.update({
            "has_receipt": True,
            "verdict": payload["verdict"]["decided"],
            "grounded": payload["verdict"]["grounded"],
            "custom_code": payload["static"].get("shipped_python_files") or [],
            "repair_attempted": payload["repair"]["attempted"],
            "repair_ok": payload["repair"]["ok"],
            "equivalent": eq.get("equivalent"),
            "prompt_count": eq.get("prompt_count"),
            "original_capability_ops": len(eq.get("original_capability_events") or []),
            "sanitized_capability_ops": len(eq.get("sanitized_capability_events") or []),
        })
    else:
        row["stderr_tail"] = (proc.stderr or proc.stdout)[-300:]
    return row


def main() -> int:
    manifest = json.loads((ROOT / "corpus" / "MANIFEST.json").read_text())
    cases = [c for c in manifest["cases"] if c["label"] == "undeclared"]
    REPORTS.mkdir(exist_ok=True)

    rows = []
    for i, case in enumerate(cases, 1):
        print(f"[{i}/{len(cases)}] {case['name']} ...", flush=True)
        started = time.time()
        row = inspect(case["name"])
        row.update({"name": case["name"], "category": case["category"],
                    "elapsed_s": round(time.time() - started, 1)})
        rows.append(row)
        print(f"      verdict={row.get('verdict')} grounded={row.get('grounded')} "
              f"repair_ok={row.get('repair_ok')} equivalent={row.get('equivalent')} "
              f"({row['elapsed_s']}s)", flush=True)

    with_code = [r for r in rows if r.get("custom_code")]
    blocked = [r for r in rows if r.get("verdict") == "BLOCK"]
    attempted = [r for r in rows if r.get("repair_attempted")]
    repaired = [r for r in attempted if r.get("repair_ok")]
    verified = [r for r in attempted if r.get("equivalent")]

    report = {
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "n": len(rows),
        "with_custom_code": len(with_code),
        "blocked": len(blocked),
        "repair_attempted": len(attempted),
        "repair_ok": len(repaired),
        "repair_verified": len(verified),
        "rows": rows,
        "note": ("Repair is only attempted when the verdict is a grounded BLOCK, and an "
                 "artifact whose payload is a pickle ships no custom code to repair."),
    }
    (REPORTS / "repair-eval.json").write_text(json.dumps(report, indent=2), encoding="utf-8")

    def rate(a, b):
        return "n/a" if not b else f"{a}/{b} ({a / b:.0%})"

    lines = [
        "# Repair evaluation",
        "",
        f"All {len(rows)} artifacts with undeclared behaviour, run end to end. Every number is read "
        "back from the signed receipt, so this measures what the product emits.",
        "",
        "| measure | result |",
        "|---|---|",
        f"| blocked by the local model (grounded) | {rate(len(blocked), len(rows))} |",
        f"| repair attempted (needs a grounded BLOCK) | {rate(len(attempted), len(blocked))} |",
        f"| repair produced and passed the capability gate | {rate(len(repaired), len(attempted))} |",
        f"| repair **verified by output-equivalence** | {rate(len(verified), len(attempted))} |",
        "",
        "## Per artifact", "",
        "| artifact | category | custom code | verdict | repair ok | equivalent | prompts | caps orig → repaired |",
        "|---|---|---|---|---|---|---|---|",
    ]
    for r in rows:
        lines.append(
            f"| `{r['name']}` | {r['category']} | {'yes' if r.get('custom_code') else 'no'} | "
            f"{r.get('verdict', '—')} | {r.get('repair_ok', '—')} | {r.get('equivalent', '—')} | "
            f"{r.get('prompt_count', '—')} | {r.get('original_capability_ops', '—')} → "
            f"{r.get('sanitized_capability_ops', '—')} |")
    lines += ["", report["note"], ""]
    (REPORTS / "repair-eval.md").write_text("\n".join(lines), encoding="utf-8")

    print("\n" + "\n".join(lines[:12]))
    print(f"\nwrote {REPORTS / 'repair-eval.md'} and repair-eval.json")
    return 0


if __name__ == "__main__":
    sys.exit(main())
