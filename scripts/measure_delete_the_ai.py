#!/usr/bin/env python3
"""Measure the organisers' Core Test: what happens if you delete the AI call?

Their guidelines state the bar exactly:

    "The AI has to do real work inside your product, not just talk to the user. A baseline
     check would be: if you deleted the AI call from your codebase, would the product still
     do its job? If yes, it doesn't qualify."

This is the measurement rather than an argument. It runs the same artifacts through the same
pipeline with the model endpoint pointed at a closed port — the model call is, in effect,
deleted — and reports what the product can still decide.

    python scripts/measure_delete_the_ai.py

Writes reports/delete-the-ai.json and reports/delete-the-ai.md.
"""

from __future__ import annotations

import json
import shutil
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

import quarantine.llm as llm                          # noqa: E402
from quarantine.agents.supervisor import run_case     # noqa: E402

CORPUS = ROOT / "corpus"
REPORTS = ROOT / "reports"
DEAD_ENDPOINT = "http://127.0.0.1:9/v1/chat/completions"   # port 9: discard, closed


def _run(cases: list[tuple[str, Path]], work: Path) -> list[dict]:
    rows = []
    for label, path in cases:
        out = work / (path.name or "case")
        try:
            outcome = run_case(path, out)
            rows.append({"artifact": path.name, "label": label,
                         "verdict": outcome.decided, "escalated": outcome.escalated,
                         "reason": (outcome.escalation_reason or "")[:160],
                         "agents": outcome.board.agents()})
        except Exception as exc:                       # noqa: BLE001
            rows.append({"artifact": path.name, "label": label, "verdict": "ERROR",
                         "escalated": True, "reason": f"{type(exc).__name__}: {exc}"[:160],
                         "agents": []})
    return rows


def _summarise(rows: list[dict]) -> dict:
    return {
        "n": len(rows),
        "allowed": sum(1 for r in rows if r["verdict"] == "ALLOW"),
        "blocked": sum(1 for r in rows if r["verdict"] == "BLOCK"),
        "escalated": sum(1 for r in rows if r["escalated"]),
    }


def main() -> int:
    manifest = json.loads((CORPUS / "MANIFEST.json").read_text(encoding="utf-8"))
    entries = manifest.get("cases", manifest) if isinstance(manifest, dict) else manifest
    cases = [(e.get("label", "?"), CORPUS / e["name"]) for e in entries]
    # Guard on existence: passing a non-existent path to the container made Docker create it
    # as an empty root-owned mount point inside corpus/, which a test then caught.
    extra = ROOT / "corpus" / "probe-missing-dep"
    if extra.exists():
        cases.append(("unlabelled", extra))

    work = Path(tempfile.mkdtemp(prefix="delete-the-ai-"))
    try:
        # WITH the model: the numbers already published in reports/corpus-eval.json.
        baseline = json.loads((REPORTS / "corpus-eval.json").read_text(encoding="utf-8"))

        # WITHOUT the model: the same pipeline, with the model endpoint unreachable.
        original, llm.URL = llm.URL, DEAD_ENDPOINT
        try:
            without = _run(cases, work / "without")
        finally:
            llm.URL = original
    finally:
        shutil.rmtree(work, ignore_errors=True)

    with_model = {"n": baseline["n"], "allowed": baseline["allowed"],
                  "blocked": baseline["quarantine"]["tp"],
                  "escalated": baseline["escalated"]}
    without_model = _summarise(without)

    report = {
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "core_test": ("if you deleted the AI call from your codebase, would the product still "
                      "do its job?"),
        "with_model": with_model,
        "without_model": without_model,
        "without_model_rows": without,
        "note": ("The model was made unreachable by pointing the endpoint at a closed port, so "
                 "this measures the pipeline without the AI rather than a description of it."),
    }
    REPORTS.mkdir(exist_ok=True)
    (REPORTS / "delete-the-ai.json").write_text(json.dumps(report, indent=2), encoding="utf-8")

    lines = [
        "# The Core Test, measured: what is left if you delete the AI call", "",
        f"*\"{report['core_test']}\"* — the organisers' own baseline check.", "",
        "Same artifacts, same pipeline. The only change is that the model endpoint points at a closed port,",
        "so the AI call is effectively deleted.", "",
        "| | with the model | **without the model** |", "|---|---|---|",
        f"| artifacts decided ALLOW | **{with_model['allowed']}** | **{without_model['allowed']}** |",
        f"| artifacts decided BLOCK | **{with_model['blocked']}** | **{without_model['blocked']}** |",
        f"| escalated to a human (UNKNOWN) | {with_model['escalated']} | **{without_model['escalated']} of {without_model['n']}** |",
        "",
        "**What remains is a syscall trace and an AST capability list.** The deterministic half of the",
        "system still does everything it was always able to do — containment, the audit-hook trace, the",
        "capability graph, the equivalence check, the signing. What it cannot do is *decide*: with no model",
        "there is no verdict, so every artifact goes to a human. The product does not degrade to a",
        "scanner; it degrades to an escalation queue.", "",
        "Note what this does **not** claim. The AI is load-bearing for the decision, not for the safety:",
        "an artifact is executed in a contained box with the network off whether or not a model is",
        "reachable, and an unreachable model can never produce an `ALLOW`. The failure mode of a model",
        "outage is *too much caution*, which is the direction a security gate should fail in.", "",
        "## Per artifact, with the model deleted", "",
        "| artifact | truth | verdict | escalated | agents that ran |",
        "|---|---|---|---|---|",
    ]
    for r in without:
        lines.append(f"| `{r['artifact']}` | {r['label']} | {r['verdict']} | {r['escalated']} | "
                     f"{', '.join(r['agents']) or '-'} |")
    lines += ["", report["note"], ""]
    (REPORTS / "delete-the-ai.md").write_text("\n".join(lines), encoding="utf-8")

    print(f"with the model : {with_model}")
    print(f"without        : {without_model}")
    print(f"\nwrote {REPORTS / 'delete-the-ai.md'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
