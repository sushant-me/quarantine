#!/usr/bin/env python3
"""Compare two local analyst models on identical evidence.

The repository tells the truth about a weakness it has: at 3B the analyst sometimes abstains
where the evidence is complete, and an abstention escalates a case that could have been
decided. `LIMITATIONS.md` says the remedy is a larger open-weight model and that it is a
configuration change rather than a code change. This script exists to TEST that claim instead
of asserting it.

It isolates exactly one variable — the model — by running only the analyst stage, on the same
evidence, for the same artifacts, and recording the verdict, grounding and latency:

    ./scripts/serve_model.sh &
    python scripts/compare_analyst_models.py --label 3b --out reports/model-3b.json
    MODEL=.../qwen2.5-coder-7b-instruct-q4_k_m.gguf ./scripts/serve_model.sh &
    python scripts/compare_analyst_models.py --label 7b --out reports/model-7b.json

Then diff the two JSON files: `abstained` is the number this is about.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from quarantine.agents.supervisor import _declared, _shipped_code     # noqa: E402
from quarantine.sandbox.execute import run_trace                      # noqa: E402
from quarantine.semantic.analyst import analyse_artifact              # noqa: E402
from quarantine.static.scan import static_pass                        # noqa: E402

# The decisive subset: benign controls where an abstention is a false escalation, undeclared
# probes where an abstention is a missed block, and the two real remote-code models that
# actually exercise the custom-Python path.
SUBSET = [
    ("control", ROOT / "corpus" / "benign-tiny-model"),
    ("control", ROOT / "corpus" / "benign-two-functions"),
    ("control", ROOT / "corpus" / "benign-typing-only"),
    ("control", ROOT / "corpus" / "benign-unicode"),
    ("undeclared", ROOT / "corpus" / "probe-custom-generate"),
    ("undeclared", ROOT / "corpus" / "probe-file-read"),
    ("undeclared", ROOT / "corpus" / "probe-subprocess"),
    ("undeclared", ROOT / "corpus" / "probe-zip-checkpoint"),
    ("undeclared", ROOT / "corpus" / "probe-lazy-trigger"),
    ("real-remote-code", ROOT / "corpus-nepali" / "indic-trans2-rotary"),
    ("real-remote-code", ROOT / "corpus-nepali" / "nepali-voice-engine"),
]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--label", required=True, help="name for this model, e.g. 3b")
    ap.add_argument("--out", required=True)
    args = ap.parse_args()

    work = ROOT / "runs" / f"model-compare-{args.label}"
    work.mkdir(parents=True, exist_ok=True)

    import quarantine.llm as llm
    from quarantine.modelinfo import resolve_model
    model_name = resolve_model(llm.MODEL)

    rows = []
    for kind, path in SUBSET:
        if not path.exists():
            rows.append({"artifact": path.name, "kind": kind, "skipped": "not present"})
            continue
        started = time.time()
        static = static_pass(path)
        trace = run_trace(path, work / path.name)
        events = trace.get("events", [])
        execution = trace.get("execution") or trace
        analysis = analyse_artifact(
            _declared(path), _shipped_code(path, static.get("custom_code_files") or []),
            events, static, execution=execution,
        )
        verdict = (analysis.get("verdict") or {}).get("verdict")
        cap = len(__import__("quarantine.events", fromlist=["capability_events"])
                  .capability_events(events))
        rows.append({
            "artifact": path.name, "kind": kind,
            "verdict": verdict or ("UNREACHABLE" if not analysis.get("reachable") else "NO_JSON"),
            "abstained": verdict == "UNKNOWN",
            "grounded": bool(analysis.get("grounded")),
            "cited": analysis.get("cited_ids"),
            "capability_events": cap,
            "observed": bool(analysis.get("reachable")),
            "elapsed_s": round(time.time() - started, 1),
        })
        flag = "ABSTAIN" if rows[-1]["abstained"] else "       "
        print(f"  {flag} {path.name:26} {rows[-1]['verdict']:10} "
              f"cap={cap} grounded={rows[-1]['grounded']} {rows[-1]['elapsed_s']:>5}s", flush=True)

    summary = {
        "label": args.label, "model": model_name,
        "artifacts": len([r for r in rows if "skipped" not in r]),
        "abstained": sum(1 for r in rows if r.get("abstained")),
        "unreachable": sum(1 for r in rows if r.get("verdict") == "UNREACHABLE"),
        "mean_elapsed_s": round(
            sum(r.get("elapsed_s", 0) for r in rows) / max(1, len([r for r in rows if "skipped" not in r])), 1),
    }
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps({"summary": summary, "rows": rows}, indent=2), encoding="utf-8")
    print(f"\n{summary}\nwrote {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
