#!/usr/bin/env python3
"""Machine-check the eligibility gate instead of asserting it.

Every item the challenge requires is checked here, and anything that cannot be
checked is reported as such rather than counted as a pass.

The important difference from a naive checker: the AI-usage disclosure is not
grepped for words. Every `path::symbol` it names is **loaded and resolved**. A
disclosure that names a function which does not exist is a false statement, and it
fails here — this exact failure mode (a document naming two symbols that did not
exist, passing a regex-based check) was found in a sibling codebase and is why this
checker resolves symbols.

    python scripts/check_eligibility.py
    python scripts/check_eligibility.py --json
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

# Vendors whose hosted inference is not permitted anywhere in this repository.
VENDOR_PATTERN = re.compile(
    r"\b("
    r"openai|anthropic|claude|gemini|azure[_-]?openai|bedrock|vertex[_-]?ai|"
    r"groq|cohere|replicate|perplexity|huggingface[_-]?inference|api\.together"
    r")\b",
    re.IGNORECASE,
)
SYMBOL_PATTERN = re.compile(r"([A-Za-z0-9_./-]+\.py)::([A-Za-z_][A-Za-z0-9_]*)")

REQUIRED_FILES = [
    ("LICENSE", "licence present"),
    ("README.md", "README"),
    ("SUBMISSION.md", "submission index"),
    ("LIMITATIONS.md", "limitations and future improvements"),
    ("docs/AI-USAGE.md", "AI usage disclosure"),
    ("corpus/MANIFEST.json", "the labeled corpus is published"),
    ("tests", "tests present"),
]


def _load_symbol(rel_path: str, symbol: str) -> tuple[bool, str]:
    """Actually import the file and get the attribute. No text matching."""
    path = ROOT / rel_path
    if not path.exists():
        return False, "file does not exist"
    name = "eligibility_probe_" + re.sub(r"\W", "_", rel_path)
    try:
        spec = importlib.util.spec_from_file_location(name, path)
        module = importlib.util.module_from_spec(spec)
        sys.modules[name] = module
        spec.loader.exec_module(module)
    except Exception as exc:                       # noqa: BLE001 - report, never crash
        return False, f"could not import: {type(exc).__name__}: {str(exc)[:90]}"
    if not hasattr(module, symbol):
        return False, "module imported but has no such symbol"
    return True, "resolved"


# Which first segments count as a claim about this repository.
#
# `runs/` is deliberately absent: it is generated evidence produced by running the
# documented commands, so a document naming an output path there is describing what
# the reader will see, not asserting that the file is committed. Everything under
# the directories below is authored content and must resolve.
TOP_LEVEL_DIRS = {"src", "scripts", "tests", "corpus", "docs", "reports", ".github"}
TOP_LEVEL_FILES = {"README.md", "SUBMISSION.md", "LIMITATIONS.md", "SPIKE-RESULTS.md", "LICENSE", "pytest.ini"}
BACKTICK_PATH = re.compile(r"`([A-Za-z0-9_./-]+\.(?:md|py|json|ya?ml|txt|toml|sh|ini))`")
MD_LINK_PATH = re.compile(r"\]\(([A-Za-z0-9_./-]+\.(?:md|py|json|ya?ml|txt|toml|sh|ini))\)")


def _repo_paths_in(text: str) -> set[str]:
    """Tokens that are meant as *repository* paths.

    Scoped deliberately: an artifact-relative name like `custom_generate/generate.py`
    or a bare `pytorch_model.bin` appears in prose about model artifacts and is not a
    claim about this repository. A path counts only when its first segment is a real
    top-level directory or file here.
    """
    found: set[str] = set()
    for match in list(BACKTICK_PATH.findall(text)) + list(MD_LINK_PATH.findall(text)):
        if "://" in match or any(ch in match for ch in "*?["):
            continue
        token = match.split("::")[0].lstrip("./")
        head = token.split("/")[0]
        if head in TOP_LEVEL_DIRS or token in TOP_LEVEL_FILES or head in TOP_LEVEL_FILES:
            found.add(token)
    return found


def check_doc_paths() -> list[dict]:
    """Every repository path a document points at must exist.

    This is the exact defect class found in a sibling codebase: a document cited a
    path that did not resolve. Symbols are resolved (above); paths are checked here.
    """
    docs = ["README.md", "SUBMISSION.md", "LIMITATIONS.md", "SPIKE-RESULTS.md"]
    docs += [str(p.relative_to(ROOT)) for p in sorted((ROOT / "docs").glob("*.md"))]
    missing: list[str] = []
    checked = 0
    for rel in docs:
        path = ROOT / rel
        if not path.exists():
            continue
        for ref in sorted(_repo_paths_in(path.read_text(encoding="utf-8"))):
            checked += 1
            if not (ROOT / ref).exists():
                missing.append(f"{rel} -> {ref}")
    return [{"check": "documented repository paths resolve", "what": f"{checked} references in {len(docs)} docs",
             "ok": not missing,
             "detail": "all resolve" if not missing else "; ".join(missing[:4])}]


def check_files() -> list[dict]:
    out = []
    for rel, label in REQUIRED_FILES:
        ok = (ROOT / rel).exists()
        out.append({"check": f"file: {rel}", "what": label, "ok": ok,
                    "detail": "present" if ok else "MISSING"})
    return out


def check_licence() -> list[dict]:
    text = (ROOT / "LICENSE").read_text(encoding="utf-8", errors="replace") if (ROOT / "LICENSE").exists() else ""
    recognized = "Apache License" in text or "MIT License" in text
    return [{"check": "licence is a real, recognized licence", "what": "LICENSE",
             "ok": recognized, "detail": "Apache-2.0" if "Apache License" in text
             else ("MIT" if "MIT License" in text else "unrecognized or missing")}]


def _docstring_lines(source: str) -> set[int]:
    """Line numbers occupied by docstrings.

    A vendor named in prose is not an endpoint. Scanning raw text flagged our own
    docstring ("OpenAI-style servers use `id`") as if it were a call — so docstrings
    are excluded, while ordinary string literals are still scanned, because a real
    endpoint would live in one.
    """
    import ast

    lines: set[int] = set()
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return lines
    for node in ast.walk(tree):
        if not isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        body = getattr(node, "body", None)
        if not body:
            continue
        first = body[0]
        if isinstance(first, ast.Expr) and isinstance(first.value, ast.Constant) \
                and isinstance(first.value.value, str):
            start = first.lineno
            end = getattr(first, "end_lineno", start)
            lines.update(range(start, end + 1))
    return lines


def check_no_vendor_inference() -> list[dict]:
    offenders = []
    scanned = 0
    for base in ("src", "scripts"):
        for path in sorted((ROOT / base).rglob("*.py")):
            if path.name == Path(__file__).name:
                continue                      # this file names the vendors on purpose
            scanned += 1
            source = path.read_text(encoding="utf-8", errors="replace")
            skip = _docstring_lines(source)
            for lineno, line in enumerate(source.splitlines(), 1):
                if lineno in skip or line.lstrip().startswith("#"):
                    continue
                if VENDOR_PATTERN.search(line):
                    offenders.append(f"{path.relative_to(ROOT)}:{lineno}")
    return [{"check": "no proprietary inference endpoint in code", "what": f"{scanned} python files",
             "ok": not offenders,
             "detail": "none" if not offenders else f"found in {offenders[:5]}"}]


def check_disclosure_symbols() -> list[dict]:
    doc = ROOT / "docs/AI-USAGE.md"
    if not doc.exists():
        return [{"check": "disclosure symbols resolve", "what": "-", "ok": False,
                 "detail": "docs/AI-USAGE.md missing"}]
    text = doc.read_text(encoding="utf-8")
    pairs = sorted(set(SYMBOL_PATTERN.findall(text)))
    if not pairs:
        return [{"check": "disclosure symbols resolve", "what": "-", "ok": False,
                 "detail": "no path::symbol entries found in the disclosure"}]
    out = []
    for rel, symbol in pairs:
        ok, detail = _load_symbol(rel, symbol)
        out.append({"check": f"disclosure symbol {rel}::{symbol}", "what": "AI entry point",
                    "ok": ok, "detail": detail})
    return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()

    results: list[dict] = []
    results += check_files()
    results += check_licence()
    results += check_no_vendor_inference()
    results += check_doc_paths()
    results += check_disclosure_symbols()

    failures = [r for r in results if not r["ok"]]
    if args.json:
        print(json.dumps({"results": results, "failures": len(failures)}, indent=2))
    else:
        width = max(len(r["check"]) for r in results)
        for r in results:
            print(f"{'OK  ' if r['ok'] else 'FAIL'}  {r['check']:<{width}}  {r['detail']}")
        print()
        print(f"{len(results) - len(failures)}/{len(results)} checks pass")
        if failures:
            print("ELIGIBILITY GATE FAILED")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
