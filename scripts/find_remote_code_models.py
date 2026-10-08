#!/usr/bin/env python3
"""Find models that ship **custom Python** — the ones that force `trust_remote_code=True`.

Why this matters more than any other artifact class: a repository whose `config.json` sets
`auto_map` requires the user to run the author's `modeling_*.py` on their own machine, by
design. That is the risk this project exists for, and a scanner that only reads pickle
opcodes never opens those files at all.

This searches the Hub for Nepali/Indic repositories and reports which ones ship `.py` files
or declare `auto_map`. Network only; writes reports/remote-code-models.json.

    python scripts/find_remote_code_models.py
"""

from __future__ import annotations

import json
import sys
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REPORTS = ROOT / "reports"

QUERIES = ["nepali", "nepal", "devanagari", "nepali-llm", "nepberta", "indic", "himalayan"]
LIMIT = 100


def _get(url: str, timeout: int = 25):
    req = urllib.request.Request(url, headers={"User-Agent": "quarantine/0.2 (research)"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode())


def search() -> dict[str, dict]:
    found: dict[str, dict] = {}
    for q in QUERIES:
        try:
            models = _get(f"https://huggingface.co/api/models?search={q}&limit={LIMIT}&sort=downloads&direction=-1")
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            print(f"query {q!r} failed: {type(exc).__name__}", flush=True)
            continue
        for m in models:
            mid = m.get("modelId")
            if mid and mid not in found:
                found[mid] = {"downloads": m.get("downloads", 0),
                              "tags": m.get("tags", []), "queries": [q]}
            elif mid:
                found[mid]["queries"].append(q)
        print(f"query {q!r}: {len(models)} results, {len(found)} unique so far", flush=True)
    return found


def main() -> int:
    REPORTS.mkdir(exist_ok=True)
    models = search()
    print(f"\n{len(models)} unique repositories; checking each for custom code\n", flush=True)

    with_code: list[dict] = []
    auto_map: list[dict] = []
    for i, (mid, meta) in enumerate(sorted(models.items(), key=lambda kv: -kv[1]["downloads"]), 1):
        try:
            info = _get(f"https://huggingface.co/api/models/{mid}?blobs=true")
        except Exception:                              # noqa: BLE001 - keep going
            continue
        files = [s["rfilename"] for s in info.get("siblings", [])]
        pys = [f for f in files if f.endswith(".py")]
        if pys:
            entry = {"model": mid, "downloads": meta["downloads"], "py_files": pys,
                     "has_auto_map": False}
            try:
                cfg = json.loads(
                    urllib.request.urlopen(f"https://huggingface.co/{mid}/raw/main/config.json",
                                           timeout=20).read().decode())
                entry["has_auto_map"] = bool(cfg.get("auto_map"))
                entry["architectures"] = cfg.get("architectures")
            except Exception:                          # noqa: BLE001
                pass
            with_code.append(entry)
            if entry["has_auto_map"]:
                auto_map.append(entry)
            print(f"  [{i}/{len(models)}] CUSTOM CODE  {mid}  py={pys[:3]}  auto_map={entry['has_auto_map']}",
                  flush=True)
        elif i % 25 == 0:
            print(f"  [{i}/{len(models)}] ... nothing yet", flush=True)

    report = {
        "queries": QUERIES,
        "repositories_checked": len(models),
        "with_python_files": len(with_code),
        "with_auto_map": len(auto_map),
        "with_code": with_code,
        "auto_map": auto_map,
        "note": ("A repository with `auto_map` requires `trust_remote_code=True`: the user runs the "
                 "author's Python on their own machine by design. Neither picklescan nor fickling "
                 "opens a .py file, which is the coverage hole this project targets."),
    }
    (REPORTS / "remote-code-models.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(f"\nchecked {len(models)} repositories")
    print(f"  shipping .py files: {len(with_code)}")
    print(f"  declaring auto_map (trust_remote_code=True): {len(auto_map)}")
    for e in auto_map[:10]:
        print(f"    - {e['model']}  ({e['downloads']} downloads)  {e['py_files']}")
    print(f"\nwrote {REPORTS / 'remote-code-models.json'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
