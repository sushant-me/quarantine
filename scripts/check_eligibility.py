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
    ("CONTRIBUTING.md", "contribution guide"),
    ("SECURITY.md", "vulnerability disclosure policy"),
    ("requirements.txt", "runtime dependencies are stated"),
    ("requirements-dev.txt", "measurement dependencies are stated separately"),
    ("docs/AI-USAGE.md", "AI usage disclosure"),
    ("docs/EVENT-REQUIREMENTS.md", "the event's requirements, mapped"),
    ("docs/NEPAL.md", "what this does for the Nepal community"),
    ("scripts/fetch_nepali_models.py", "the Nepali control set is reproducible"),
    ("scripts/find_remote_code_models.py", "the remote-code search is reproducible"),
    ("docker/Dockerfile.analysis", "the analysis image is defined"),
    ("scripts/build_analysis_image.sh", "the analysis image is buildable"),
    ("scripts/measure_image_baseline.py", "the noise floor is measurable"),
    ("scripts/eval_third_party.py", "the third-party corpus evaluation is reproducible"),
    ("reports/third-party-eval.md", "the third-party result is published"),
    ("scripts/measure_delete_the_ai.py", "the Core Test is measurable"),
    ("scripts/compare_analyst_models.py", "the model comparison is measurable"),
    ("reports/model-3b.json", "the smaller model's measurement is published"),
    ("reports/model-7b.json", "the larger model's measurement is published"),
    ("reports/delete-the-ai.md", "the Core Test result is published"),
    ("tools/verify_receipt_standalone.py", "receipts verify without this codebase"),
    ("presentation/quarantine-demo-day.html", "the Demo Day deck is present"),
    ("presentation/quarantine-project-idea.html", "the project-idea document source"),
    ("presentation/Quarantine-Project-Idea.pdf", "the project-idea PDF all these documents explain"),
    ("pyproject.toml", "the package is installable, so no documented command needs PYTHONPATH"),
    ("scripts/build_demo_narration.py", "the narration is generated, not hand-timed"),
    ("presentation/quarantine-demo-narration.srt", "the demo video has a narration script"),
    ("scripts/build_demo_narration.py", "the narration is generated, not hand-timed"),
    ("runs/probe/keys/quarantine.pub.pem", "the public key is published so anyone can verify"),
    ("baselines/python_3.12-slim.jsonl", "the default image's noise floor is recorded"),
    ("docs/DEMO-SCRIPT.md", "demo script"),
    ("reports/video/quarantine-demo.mp4", "demo video (required deliverable)"),
    ("corpus/MANIFEST.json", "the labeled corpus is published"),
    ("tests", "tests present"),
]

# "Makes its source, license, model, and key dependencies easy to verify" — the organizers'
# own phrase in "What does a strong entry look like?". So it is checked, not assumed.
README_MUST_STATE = [
    ("Apache-2.0", "the licence"),
    ("qwen2.5-coder-3b", "the exact model"),
    ("llama.cpp", "how the model is served"),
    ("requirements.txt", "where dependencies are pinned"),
]

# The minimum requirements, in the organizers' words. Each must appear in the mapping doc,
# so the mapping cannot silently drift away from what the event actually asks for.
EVENT_MINIMUM_REQUIREMENTS = [
    "source code is public",
    "limitations/future improvements",
    "functional demonstration",
    "a short demo showing the problem",
    "part of core logic",
    "naming the exact file/function",
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


def _mp4_duration_seconds(path: Path) -> float | None:
    """Read an MP4's duration from its `mvhd` box, with no external tool.

    The first version of this check shelled out to ffprobe, and CI failed on the very next push
    because the runner has no ffprobe: a gate that breaks the build when an optional binary is
    absent is worse than the drift it was written to catch. The `mvhd` box carries timescale and
    duration in big-endian, which is all this needs.
    """
    try:
        data = path.read_bytes()
    except OSError:
        return None
    offset = data.find(b"mvhd")
    if offset < 0 or offset + 32 > len(data):
        return None
    cursor = offset + 4                       # past the "mvhd" type field
    version = data[cursor]
    if version == 1:
        timescale = int.from_bytes(data[cursor + 20:cursor + 24], "big")
        duration = int.from_bytes(data[cursor + 24:cursor + 32], "big")
    else:
        timescale = int.from_bytes(data[cursor + 12:cursor + 16], "big")
        duration = int.from_bytes(data[cursor + 16:cursor + 20], "big")
    return (duration / timescale) if timescale else None


def check_quoted_video_duration_is_true() -> list[dict]:
    """A duration quoted next to the demo video must match the video.

    `docs/EVENT-REQUIREMENTS.md` said the demo was 2:31 when it is 3:02 - the video was rebuilt
    with exact per-scene timing and the sentence describing it was not. A judge checking one
    document against the artifact finds that in ten seconds, so the comparison is a script's job.
    """
    import re as _re

    video = ROOT / "reports" / "video" / "quarantine-demo.mp4"
    if not video.exists():
        return [{"check": "the quoted demo duration is true", "what": "docs", "ok": False,
                 "detail": "the demo video is missing"}]
    seconds = _mp4_duration_seconds(video)
    if seconds is None:
        return [{"check": "the quoted demo duration is true", "what": "docs", "ok": False,
                 "detail": "could not read the mp4 duration from the file"}]
    true_stamp = f"{int(seconds) // 60}:{int(round(seconds)) % 60:02d}"

    bad = []
    for path in sorted(ROOT.rglob("*.md")):
        if ".git" in path.parts or "session" in path.parts:
            continue
        for number, line in enumerate(path.read_text(encoding="utf-8",
                                                    errors="replace").splitlines(), 1):
            # Only a stamp on a line that names the video FILE is a claim about the video.
            # Matching "demo video" as well flagged the live demo script's planned runtime
            # ("3:00") as if it described the recording, which it does not.
            if "quarantine-demo.mp4" not in line:
                continue
            for stamp in _re.findall(r"\b(\d{1,2}:\d{2})\b", line):
                if stamp != true_stamp:
                    bad.append(f"{path.relative_to(ROOT)}:{number} says {stamp}")
    return [{"check": "the quoted demo duration is true", "what": "docs", "ok": not bad,
             "detail": f"every quote matches {true_stamp}" if not bad else "; ".join(bad[:3])}]


def check_curated_receipts_match_the_documented_format() -> list[dict]:
    """Every field the README's receipt table names must exist in the published receipt.

    The README's table IS the receipt format's contract, and the curated receipt in `runs/probe`
    is its worked example — the file the verification recipe in the same section points at. It
    drifted once: the verdict gained a stated ground, the receipts kept the old shape, and the
    table did not exist yet. This check makes the documentation and the artifact fail together.
    """
    import base64
    import json as _json
    import re as _re

    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    documented = _re.findall(r"^\| `([a-z_.]+)` \|", readme, _re.M)
    receipt = ROOT / "runs" / "probe" / "receipt.json"
    out: list[dict] = []
    if not documented:
        return [{"check": "the receipt format is documented", "what": "receipt", "ok": False,
                 "detail": "no field table found in README.md"}]
    if not receipt.exists():
        return [{"check": "the receipt format is documented", "what": "receipt", "ok": False,
                 "detail": "runs/probe/receipt.json is missing"}]
    try:
        raw = _json.loads(receipt.read_text(encoding="utf-8"))
        payload = _json.loads(base64.b64decode(raw["payload"])) if "payload" in raw else raw
    except Exception as exc:                                      # noqa: BLE001
        return [{"check": "the receipt format is documented", "what": "receipt", "ok": False,
                 "detail": f"{type(exc).__name__}: {exc}"}]

    def paths(node: dict, prefix: str = "") -> set:
        found = set()
        for key, value in node.items():
            found.add(prefix + key)
            if isinstance(value, dict):
                found |= paths(value, prefix + key + ".")
        return found

    have = paths(payload)
    missing = [field for field in documented if field not in have]
    out.append({"check": "the documented receipt fields exist in the published receipt",
                "what": "receipt", "ok": not missing,
                "detail": (f"{len(documented)} documented fields, all present in a "
                           f"{payload.get('verdict', {}).get('decided')} receipt"
                           if not missing else f"documented but absent: {missing}")})
    return out


def check_no_generated_artifacts_are_tracked() -> list[dict]:
    """Nothing regenerable may be tracked under runs/ except the curated evidence.

    This exists because a measurement script wrote `runs/model-compare-*/` and 44 trace files
    went into a commit: `.gitignore` listed scratch directories by name, which only catches the
    names someone remembered. A rule that depends on attention is not a rule.
    """
    import subprocess
    allowed = ("runs/probe/", "runs/benign/")
    try:
        tracked = subprocess.run(["git", "ls-files", "runs"], cwd=ROOT, capture_output=True,
                                 text=True, timeout=60).stdout.split()
    except Exception as exc:                                    # noqa: BLE001
        return [{"check": "no generated artifacts are tracked", "what": "hygiene", "ok": False,
                 "detail": f"could not list tracked files: {exc}"}]
    stray = [f for f in tracked if not f.startswith(allowed)]
    return [{"check": "no generated artifacts are tracked", "what": "hygiene",
             "ok": not stray, "detail": (f"{len(tracked)} curated evidence files" if not stray
                                         else f"regenerable output is tracked: {stray[:3]}")}]


def check_presentations_are_self_contained() -> list[dict]:
    """The deck and the project-idea document must work with the network off.

    That is the theme, and a document that pulls a font from a CDN fails in the room it is
    presented in. The PDF is checked too: it is what gets shared, so it has to exist and be
    a real document rather than a truncated render.
    """
    import re as _re
    out = []
    for rel, minimum in (("presentation/quarantine-demo-day.html", 10),
                         ("presentation/quarantine-project-idea.html", 6)):
        path = ROOT / rel
        if not path.exists():
            out.append({"check": f"{rel} is self-contained", "what": "presentation",
                        "ok": False, "detail": "missing"})
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        refs = [r for r in _re.findall(r'(?:src|href)="([^"]+)"', text) if not r.startswith("#")]
        sections = text.count('class="slide') + text.count('class="page')
        ok = not refs and sections >= minimum
        out.append({"check": f"{rel} is self-contained", "what": "presentation", "ok": ok,
                    "detail": (f"{sections} sections, no external references" if ok
                               else f"{sections} sections, external refs: {refs[:3]}")})

    pdf = ROOT / "presentation" / "Quarantine-Project-Idea.pdf"
    size = pdf.stat().st_size if pdf.exists() else 0
    header_ok = pdf.exists() and pdf.read_bytes()[:5] == b"%PDF-"
    out.append({"check": "the project-idea PDF is a real PDF", "what": "presentation",
                "ok": header_ok and size > 50_000,
                "detail": f"%PDF header, {size/1024:.0f} KB" if header_ok else "missing or not a PDF"})
    return out


def check_console_entry_point() -> list[dict]:
    """The console script named in pyproject.toml must actually resolve.

    `pip install -e .` creating the file is not the same as the file working: the entry point is
    a string until something imports it. This imports the module and takes the attribute, which
    is what setuptools' generated wrapper does at run time.
    """
    import re as _re
    out = []
    pyproject = (ROOT / "pyproject.toml")
    text = pyproject.read_text(encoding="utf-8") if pyproject.exists() else ""
    match = _re.search(r'^\s*quarantine\s*=\s*"([^"]+)"', text, _re.M)
    if not match:
        out.append({"check": "the console script resolves", "what": "packaging", "ok": False,
                    "detail": "pyproject.toml declares no quarantine entry point"})
        return out
    target = match.group(1)
    module_name, _, attribute = target.partition(":")
    rel = "src/" + module_name.replace(".", "/") + ".py"
    resolved, detail = _load_symbol(rel, attribute)
    if not resolved:
        out.append({"check": "the console script resolves", "what": "packaging", "ok": False,
                    "detail": f"quarantine -> {target}: {detail}"})
        return out
    # Existing the attribute is not the same as being usable as an entry point: testuptools'
    # wrapper calls it, so it has to be callable.
    probe = sys.modules.get("eligibility_probe_" + _re.sub(r"\W", "_", rel))
    callable_ok = callable(getattr(probe, attribute, None))
    out.append({"check": "the console script resolves", "what": "packaging", "ok": callable_ok,
                "detail": f"quarantine -> {target} "
                          f"({'imports and is callable' if callable_ok else 'resolves but is not callable'})"})
    return out


def check_licence() -> list[dict]:
    text = (ROOT / "LICENSE").read_text(encoding="utf-8", errors="replace") if (ROOT / "LICENSE").exists() else ""
    recognized = "Apache License" in text or "MIT License" in text
    return [{"check": "licence is a real, recognized licence", "what": "LICENSE",
             "ok": recognized, "detail": "Apache-2.0" if "Apache License" in text
             else ("MIT" if "MIT License" in text else "unrecognized or missing")}]


def check_verifiable_facts() -> list[dict]:
    """Source, licence, model and dependencies must be easy to verify — the event asks for it.

    Checked by substring rather than by vibes, because a README that stopped naming the
    model would otherwise keep passing.
    """
    readme = (ROOT / "README.md").read_text(encoding="utf-8", errors="replace") \
        if (ROOT / "README.md").exists() else ""
    out = []
    for needle, what in README_MUST_STATE:
        ok = needle in readme
        out.append({"check": f"README states {what}", "what": what, "ok": ok,
                    "detail": f"found {needle!r}" if ok else f"MISSING {needle!r}"})
    return out


def check_event_requirements_mapped() -> list[dict]:
    """The mapping doc must still quote the event's minimum requirements."""
    path = ROOT / "docs" / "EVENT-REQUIREMENTS.md"
    text = path.read_text(encoding="utf-8", errors="replace") if path.exists() else ""
    out = []
    for phrase in EVENT_MINIMUM_REQUIREMENTS:
        ok = phrase in text
        out.append({"check": f"requirement mapped: {phrase[:38]}", "what": "event requirement",
                    "ok": ok, "detail": "quoted and mapped" if ok else "no longer quoted"})
    return out


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
    results += check_verifiable_facts()
    results += check_console_entry_point()
    results += check_no_generated_artifacts_are_tracked()
    results += check_curated_receipts_match_the_documented_format()
    results += check_quoted_video_duration_is_true()
    results += check_presentations_are_self_contained()
    results += check_event_requirements_mapped()
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
