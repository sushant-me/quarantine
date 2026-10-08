"""The proof — what turns a repair from a claim into a fact.

Two loaders are run against the same fixed prompts in the same contained,
network-less environment. Identical outputs mean the repair preserved the
declared behaviour; different outputs mean it did not, and the repair is
rejected no matter how plausible it looked.
"""

from __future__ import annotations

import json
from pathlib import Path

from quarantine.sandbox.execute import run_call

DEFAULT_PROMPTS = ["hello world", "Quarantine probe 123", "a"]


def compare(original: Path, sanitized: Path, workdir: Path,
            prompts: list[str] | None = None) -> dict:
    prompts = prompts or DEFAULT_PROMPTS
    before_dir = workdir / "equiv_original"
    after_dir = workdir / "equiv_sanitized"
    before = run_call(original, prompts, before_dir)
    after = run_call(sanitized, prompts, after_dir)

    out_before = before.get("result", {}).get("outputs") or []
    out_after = after.get("result", {}).get("outputs") or []
    err_before = before.get("result", {}).get("error")
    err_after = after.get("result", {}).get("error")

    equivalent = (
        err_before is None and err_after is None
        and bool(out_before) and out_before == out_after
    )
    return {
        "prompts": prompts,
        "original_outputs": out_before,
        "sanitized_outputs": out_after,
        "original_error": err_before,
        "sanitized_error": err_after,
        "equivalent": equivalent,
        "note": ("identical outputs on the fixed prompt set" if equivalent
                 else "outputs differ or a run failed; the repair is rejected"),
    }


def write_report(result: dict, path: Path) -> None:
    path.write_text(json.dumps(result, indent=2), encoding="utf-8")
