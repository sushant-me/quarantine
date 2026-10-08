"""The proof — what turns a repair from a claim into a fact.

Two loaders are run against the same fixed prompts in the same contained, network-less
environment, **under the audit hook**. Two things must both hold:

1. **Identical outputs.** Different outputs reject the repair no matter how plausible
   it looked.
2. **Zero capability operations in the repaired loader.** The original may read a file
   and open a socket; the repair must do neither. This is stronger than the AST check
   in `repair/loader.py`, which only proves the source *looks* free of capability —
   this proves nothing of the kind *happened*.
"""

from __future__ import annotations

import json
from pathlib import Path

from quarantine.events import capability_events
from quarantine.sandbox.execute import run_call

# A prompt set wide enough that a loader which only works on the easy case fails here:
# case, punctuation, unicode, empty, whitespace, a tab, digits, a newline, and length.
DEFAULT_PROMPTS = [
    "hello world",
    "Quarantine probe 123",
    "a",
    "",
    "   spaced   ",
    "MiXeD cAsE with 1234 and punctuation?!",
    "नमस्ते — non-ASCII input",
    "üñïçøðé",
    "line one\nline two",
    "0",
    "\t tab and trailing space ",
    "x" * 300,
]


def _cap_pairs(events: list[dict]) -> list[list[str]]:
    return [[e["event"], e["detail"]] for e in capability_events(events)]


def compare(original: Path, sanitized: Path, workdir: Path,
            prompts: list[str] | None = None) -> dict:
    prompts = prompts or DEFAULT_PROMPTS
    before = run_call(original, prompts, workdir / "equiv_original")
    after = run_call(sanitized, prompts, workdir / "equiv_sanitized")

    res_before = before.get("result", {})
    res_after = after.get("result", {})
    out_before = res_before.get("outputs") or []
    out_after = res_after.get("outputs") or []
    err_before = res_before.get("error")
    err_after = res_after.get("error")

    caps_before = _cap_pairs(res_before.get("events") or [])
    caps_after = _cap_pairs(res_after.get("events") or [])

    outputs_identical = (
        err_before is None and err_after is None
        and len(out_before) == len(prompts) and out_before == out_after
    )
    original_ran = err_before is None
    equivalent = outputs_identical and not caps_after

    if not original_ran:
        note = ("the ORIGINAL artifact could not be executed, so equivalence is NOT established — "
                "the repair is not claimed to be proven, even though it is capability-clean")
    elif equivalent:
        note = (f"identical outputs on {len(prompts)} prompts, and the repaired loader "
                f"performed no capability operation (the original performed {len(caps_before)})")
    elif not outputs_identical:
        note = "outputs differ or a run failed; the repair is rejected"
    else:
        note = (f"outputs match, but the repaired loader still performed "
                f"{len(caps_after)} capability operation(s); the repair is rejected")

    return {
        "criterion": ("identical outputs on every prompt AND zero capability operations "
                      "by the repaired loader"),
        "prompts": prompts,
        "prompt_count": len(prompts),
        "original_outputs": out_before,
        "sanitized_outputs": out_after,
        "original_error": err_before,
        "sanitized_error": err_after,
        "original_ran": original_ran,
        "outputs_identical": outputs_identical,
        "original_capability_events": caps_before,
        "sanitized_capability_events": caps_after,
        "equivalent": equivalent,
        "note": note,
    }


def write_report(result: dict, path: Path) -> None:
    path.write_text(json.dumps(result, indent=2), encoding="utf-8")
