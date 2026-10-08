#!/usr/bin/env python3
"""Run Quarantine against a **third-party** malicious corpus.

The weakest thing about our own evidence is that the malicious artifacts are ours. This
removes that objection: `picklescan`'s maintainers publish a test corpus of malicious and
benign pickles (including payloads derived from real GHSA advisories in real libraries),
and this runs our contained observer over every sample.

What is measured, per sample:
  * does our box **observe capability** (i.e. does the payload actually do something)?  <- no model needed
  * what does picklescan say about the same bytes?

Nothing is executed outside the sandbox: `--network none`, read-only root, all capabilities
dropped, unprivileged user, bounded pids/memory/cpu, throwaway container.

    python scripts/eval_third_party.py --src /tmp/thirds/picklescan/tests/data \
                                       --src /tmp/thirds/picklescan/tests/data2

Writes reports/third-party-eval.{json,md}.
"""

from __future__ import annotations

import argparse
import json
import shutil
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from quarantine.events import capability_events             # noqa: E402
from quarantine.sandbox.execute import run_trace             # noqa: E402
from quarantine.static.scan import parse_picklescan, run_incumbents  # noqa: E402

REPORTS = ROOT / "reports"


# Their corpus names payloads after what they exercise: `maliciousN.pkl`, `benignN.pkl`,
# and one file per real advisory (`GHSA-xxxx-xxxx-xxxx.pkl`), plus a few descriptive
# exploit samples. An earlier version of this classifier only recognised `malicious`/`bad`,
# which silently filed 44 genuine GHSA advisory payloads under "unlabelled" and understated
# the malicious denominator by more than half.
_EXPLOIT_MARKERS = ("exploit", "exfiltration", "codeinjection", "urlopen", "rce",
                    "payload", "injection", "deserial")


def classify(name: str) -> str:
    low = name.lower()
    if "benign" in low:
        return "benign"
    if (low.startswith("malicious") or low.startswith("ghsa-") or low.startswith("bad_")
            or low.startswith("types_") or any(k in low for k in _EXPLOIT_MARKERS)):
        return "malicious"
    return "unlabelled"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--src", action="append", required=True, help="directory of samples")
    ap.add_argument("--limit", type=int, default=0)
    args = ap.parse_args()

    samples: list[tuple[str, Path, str]] = []
    for src in args.src:
        for path in sorted(Path(src).iterdir()):
            if path.is_file() and not path.name.endswith((".py", ".json")):
                samples.append((path.name, path, classify(path.name)))
    if args.limit:
        samples = samples[: args.limit]

    work = Path(tempfile.mkdtemp(prefix="third-party-"))
    rows: list[dict] = []
    try:
        for i, (name, path, truth) in enumerate(samples, 1):
            case = work / name
            case.mkdir(parents=True, exist_ok=True)
            shutil.copy2(path, case / path.name)          # keep their filename
            try:
                trace = run_trace(case, work / (name + ".out"), timeout=120)
                caps = capability_events(trace["events"])
                observed = bool(caps)
                exec_summary = trace.get("execution") or {}
            except Exception as exc:                       # noqa: BLE001
                caps, observed, exec_summary = [], False, {"errors": [f"{type(exc).__name__}: {exc}"]}
            try:
                inc = parse_picklescan(run_incumbents(case)["picklescan"])
            except Exception:                              # noqa: BLE001
                inc = {}
            rows.append({
                "sample": name, "truth": truth,
                "quarantine_observed": observed,
                "capability_events": [f"{e['event']}: {str(e['detail'])[:40]}" for e in caps][:4],
                "events_total": trace["event_count"] if "trace" in locals() else 0,
                "picklescan_infected": bool(inc.get("verdict_malicious")),
                "picklescan_clean": inc.get("says_clean"),
                "errors": (exec_summary.get("errors") or [])[:2],
            })
            print(f"  [{i}/{len(samples)}] {name:28} {truth:11} "
                  f"observed={'YES' if observed else 'no ':3} picklescan="
                  f"{'FLAG' if inc.get('verdict_malicious') else 'clean'}", flush=True)
    finally:
        shutil.rmtree(work, ignore_errors=True)

    def rate(truth: str, key: str) -> dict:
        group = [r for r in rows if r["truth"] == truth]
        hit = sum(1 for r in group if r[key])
        return {"n": len(group), "hit": hit, "rate": round(hit / len(group), 3) if group else None}

    malicious = [r for r in rows if r["truth"] == "malicious"]
    benign = [r for r in rows if r["truth"] == "benign"]
    report = {
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "source": "picklescan's published test corpus (github.com/mmaitre314/picklescan)",
        "n": len(rows),
        "quarantine_observes_malicious": rate("malicious", "quarantine_observed"),
        "quarantine_observes_benign": rate("benign", "quarantine_observed"),
        "picklescan_flags_malicious": rate("malicious", "picklescan_infected"),
        "picklescan_flags_benign": rate("benign", "picklescan_infected"),
        "missed_by_our_box": [r["sample"] for r in malicious if not r["quarantine_observed"]],
        "false_positive_on_benign": [r["sample"] for r in benign if r["quarantine_observed"]],
        "rows": rows,
        "note": ("This is the observation step only: does the contained run see capability? "
                 "It needs no model, and a sample we do not observe is one we could not judge "
                 "from behaviour - which is exactly what the escalation path is for."),
    }
    REPORTS.mkdir(exist_ok=True)
    (REPORTS / "third-party-eval.json").write_text(json.dumps(report, indent=2), encoding="utf-8")

    lines = [
        "# Third-party malicious corpus — picklescan's own test data", "",
        f"Source: picklescan's published test corpus (`github.com/mmaitre314/picklescan`), "
        f"**{len(malicious)} malicious and {len(benign)} benign samples**. These are not ours, "
        "and some are derived from real GHSA advisories in real libraries.", "",
        "| measure | result |", "|---|---|",
        f"| our contained run **observed capability** on malicious samples | "
        f"**{rate('malicious','quarantine_observed')['hit']}/{len(malicious)}** |",
        f"| our contained run observed capability on **benign** samples (false positives) | "
        f"**{rate('benign','quarantine_observed')['hit']}/{len(benign)}** |",
        f"| picklescan called the malicious samples infected | "
        f"**{rate('malicious','picklescan_infected')['hit']}/{len(malicious)}** |",
        f"| picklescan called the benign samples infected | "
        f"**{rate('benign','picklescan_infected')['hit']}/{len(benign)}** |",
        "", "## Malicious samples our box did **not** observe", "",
    ]
    lines += [f"- `{s}`" for s in report["missed_by_our_box"]] or ["- (none)"]
    lines += ["", "## Per sample", "",
              "| sample | truth | observed | picklescan | first capability seen |",
              "|---|---|---|---|---|"]
    for r in rows:
        lines.append(f"| `{r['sample']}` | {r['truth']} | "
                     f"{'**yes**' if r['quarantine_observed'] else 'no'} | "
                     f"{'infected' if r['picklescan_infected'] else 'clean'} | "
                     f"{(r['capability_events'] or ['-'])[0][:52]} |")
    lines += ["", report["note"], ""]
    (REPORTS / "third-party-eval.md").write_text("\n".join(lines), encoding="utf-8")

    print(f"\nmalicious observed : {rate('malicious','quarantine_observed')}")
    print(f"benign observed    : {rate('benign','quarantine_observed')}")
    print(f"picklescan malicious: {rate('malicious','picklescan_infected')}")
    print(f"\nwrote {REPORTS / 'third-party-eval.md'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
