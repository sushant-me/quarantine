#!/usr/bin/env python3
"""Run the whole labeled corpus and report honestly.

For every artifact: what the incumbent scanners say, what the contained trace captured,
and what the local model decided. Then the confusion matrices — because a detector that
blocks everything scores 100% on the malicious set and is worthless.

    python scripts/eval_corpus.py            # all cases
    python scripts/eval_corpus.py --limit 3  # quick smoke run

Writes reports/corpus-eval.json and reports/corpus-eval.md.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from quarantine.agents.supervisor import run_case               # noqa: E402

CORPUS = ROOT / "corpus"
REPORTS = ROOT / "reports"


def evaluate(name: str, workdir: Path, base: Path) -> dict:
    """One artifact through the whole agent team; reported from the outcome."""
    root = base / name
    started = time.time()
    outcome = run_case(root, workdir)
    case = outcome.case
    inc = case.static["incumbent_verdict"]
    ps, fk = inc["picklescan"], inc["fickling"]
    flagged_by = [n for n, says_clean in (("picklescan", ps["says_clean"]),
                                          ("fickling", fk["says_clean"])) if says_clean is False]
    return {
        "name": name,
        "picklescan": ps,
        "fickling": fk,
        "incumbents_flagged_by": flagged_by,
        "incumbents_flagged": bool(flagged_by),
        "static_capabilities": {k: v for k, v in case.static["capability_graph"]["capabilities"].items() if v},
        "custom_code_files": case.custom_files,
        "trace_events": len(case.events),
        "sensitive_events": [e for e in case.events
                             if e["event"] in {"socket.getaddrinfo", "file.read", "subprocess.Popen",
                                               "pickle.find_class", "os.system"}],
        "verdict": outcome.decided,
        "escalated": outcome.escalated,
        "escalation_reason": outcome.escalation_reason,
        "observed": case.observed,
        "grounded": (outcome.analysis or {}).get("grounded", False),
        "cited_ids": (outcome.analysis or {}).get("cited_ids", []),
        "mechanism": ((outcome.analysis or {}).get("verdict") or {}).get("mechanism", ""),
        "agents": outcome.board.agents(),
        "turns": outcome.turns,
        "elapsed_s": round(time.time() - started, 2),
    }


def matrix(rows: list[dict], positive, flag_key: str = "verdict") -> dict:
    tp = fp = fn = tn = 0
    for r in rows:
        truth = r["label"] == "undeclared"
        said = positive(r)
        if truth and said:
            tp += 1
        elif truth and not said:
            fn += 1
        elif not truth and said:
            fp += 1
        else:
            tn += 1
    total_pos = tp + fn
    total_neg = fp + tn
    return {
        "tp": tp, "fp": fp, "fn": fn, "tn": tn,
        "detection_rate": round(tp / total_pos, 4) if total_pos else None,
        "false_positive_rate": round(fp / total_neg, 4) if total_neg else None,
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--limit", type=int, default=0)
    ap.add_argument("--dir", default=None,
                    help="evaluate every subdirectory of this directory instead of the labeled corpus")
    ap.add_argument("--label", default="benign", help="label to assign when --dir is used")
    ap.add_argument("--prefix", default=None, help="report filename prefix")
    args = ap.parse_args()

    REPORTS.mkdir(exist_ok=True)
    if args.dir:
        base = Path(args.dir).resolve()
        cases = [{"name": d.name, "label": args.label, "category": "real-published-model",
                  "note": "third-party artifact fetched from the Hub; none of this code is ours"}
                 for d in sorted(base.iterdir()) if d.is_dir()]
        prefix = args.prefix or base.name
        title = "Third-party negative controls"
        blurb = (f"{len(cases)} real, published model repositories. Every one is expected to be benign; "
                 "any BLOCK here is a false positive.")
    else:
        base = CORPUS
        manifest = json.loads((CORPUS / "MANIFEST.json").read_text())
        cases = manifest["cases"][: args.limit] if args.limit else manifest["cases"]
        prefix = args.prefix or "corpus"
        title = "Corpus evaluation"
        blurb = (f"{len(cases)} artifacts: {sum(1 for c in cases if c['label'] == 'benign')} benign "
                 "controls, " f"{sum(1 for c in cases if c['label'] == 'undeclared')} with undeclared "
                 "behaviour. Same declared API in every case.")

    rows = []
    for i, case in enumerate(cases, 1):
        name = case["name"]
        print(f"[{i}/{len(cases)}] {name} ({case['label']}/{case['category']}) ...", flush=True)
        row = evaluate(name, REPORTS / f"eval-runs-{prefix}" / name, base)
        row.update({"label": case["label"], "category": case["category"], "note": case["note"]})
        rows.append(row)
        print(f"      incumbents flagged={row['incumbents_flagged']} "
              f"({','.join(row['incumbents_flagged_by']) or 'none'}) | "
              f"trace={row['trace_events']} | verdict={row['verdict']} "
              f"grounded={row['grounded']} | {row['elapsed_s']}s", flush=True)

    q = matrix(rows, lambda r: r["verdict"] == "BLOCK")
    inc = matrix(rows, lambda r: r["incumbents_flagged"])
    pickle_only = matrix(rows, lambda r: bool(r["picklescan"]["says_clean"] is False))
    fick = matrix(rows, lambda r: bool(r["fickling"]["says_clean"] is False))

    report = {
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "kind": prefix,
        "n": len(rows),
        "benign": sum(1 for r in rows if r["label"] == "benign"),
        "undeclared": sum(1 for r in rows if r["label"] == "undeclared"),
        "escalated": sum(1 for r in rows if r.get("escalated")),
        "allowed": sum(1 for r in rows if r["verdict"] == "ALLOW"),
        "quarantine": q,
        "incumbents_any": inc,
        "picklescan": pickle_only,
        "fickling": fick,
        "cases": rows,
        "note": ("Labels are authored by us, so this measures the auditors against a known "
                 "ground truth, not against the real world. See SPIKE-RESULTS.md. UNKNOWN is a "
                 "third outcome, not a pass: it means nothing was observed or the agents could "
                 "not agree, and it is referred to a human."),
    }
    (REPORTS / f"{prefix}-eval.json").write_text(json.dumps(report, indent=2), encoding="utf-8")

    def pct(value) -> str:
        return "n/a" if value is None else f"{value:.0%}"

    lines = [
        f"# {title}", "",
        blurb, "",
        "| auditor | caught (of %d) | detection rate | false positives (of %d) | FP rate |"
        % (report["undeclared"], report["benign"]),
        "|---|---|---|---|---|",
        f"| **Quarantine (BLOCK)** | {q['tp']} | {pct(q['detection_rate'])} | {q['fp']} | {pct(q['false_positive_rate'])} |",
        f"| picklescan | {pickle_only['tp']} | {pct(pickle_only['detection_rate'])} | {pickle_only['fp']} | {pct(pickle_only['false_positive_rate'])} |",
        f"| fickling | {fick['tp']} | {pct(fick['detection_rate'])} | {fick['fp']} | {pct(fick['false_positive_rate'])} |",
        "",
        f"Escalated to a human (UNKNOWN): **{report['escalated']} of {report['n']}** — "
        f"nothing observed, or the agents could not agree. Allowed: {report['allowed']}.",
        "",
        "## Per artifact", "",
        "| artifact | truth | category | incumbents | Quarantine | escalated | grounded | trace |",
        "|---|---|---|---|---|---|---|---|",
    ]
    for r in rows:
        who = ",".join(r["incumbents_flagged_by"]) or "clean"
        lines.append(f"| `{r['name']}` | {r['label']} | {r['category']} | {who} | "
                     f"**{r['verdict']}** | {r.get('escalated', False)} | {r['grounded']} | "
                     f"{r['trace_events']} |")
    lines += ["", report["note"], ""]
    (REPORTS / f"{prefix}-eval.md").write_text("\n".join(lines), encoding="utf-8")

    print("\n" + "\n".join(lines[:11]))
    print(f"\nwrote {REPORTS / (prefix + '-eval.md')} and {prefix}-eval.json")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
