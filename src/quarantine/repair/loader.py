"""The repair path — the second place AI is load-bearing.

A verdict blocks a build; a repair unblocks it. But a repair is only useful if it
is *verified*, so this module produces a candidate and refuses to call it done:
`proof/equivalence.py` has the final word.

**Division of labour, stated precisely** (a receipt that overstates this is a lie):
the model decides *which functions survive* and *what their bodies are*; the
harness writes the `def` lines, the indentation and the file. That split exists
because it was measured: a 1.5B and a 3B model both failed to produce a whole
module reliably, but both could produce function bodies. The model's contribution
is still the load-bearing part — the behaviour — and it is still verified.

The loop is:

    model writes bodies -> harness assembles -> gate inspects
         ^                                            |
         +---------- rejection fed back ---------------+

If it cannot produce a clean repair in a bounded number of attempts, we say so.
We do **not** silently substitute a hand-written loader, because that would make
the AI look load-bearing when it is not.
"""

from __future__ import annotations

import ast
import json
import os
import time

import quarantine.llm as llm
from quarantine.modelinfo import resolve_model
from quarantine.static.scan import CAPABILITY_CALLS, _dotted

SCHEMA = {
    "type": "object",
    "properties": {
        "functions": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "name": {"type": "string"},
                    "args": {"type": "string"},
                    "body": {"type": "array", "items": {"type": "string"}},
                },
                "required": ["name", "args", "body"],
            },
        },
        "removed": {"type": "array", "items": {"type": "string"}},
    },
    "required": ["functions", "removed"],
}

DANGEROUS_MODULES = ("socket", "subprocess", "ctypes", "urllib", "http", "requests",
                     "ssl", "pickle", "marshal", "base64", "dill", "shutil", "os", "sys")

SYSTEM = (
    "You repair untrusted Python. Return JSON only, no prose. "
    'Schema: {"functions": [{"name": <str>, "args": <str>, "body": [<one string per line>]}], '
    '"removed": [<str>]}. '
    "Keep ONLY the functions the declared API needs. Each body line is a single line of code "
    "with no leading indentation and no newline characters. Write no import statements at all: "
    "the harness adds none, so a body must not depend on them. No network, no files, no "
    "subprocess, no eval/exec."
)

MAX_ATTEMPTS = int(os.environ.get("QUARANTINE_REPAIR_ATTEMPTS", "3"))

FORBIDDEN_CAPABILITIES = ("network", "process", "dynamic_code", "filesystem",
                          "obfuscation", "deserialization")


def forbidden_in_source(source: str) -> list[str]:
    """Capabilities the sanitized loader must not have."""
    hits: list[str] = []
    try:
        tree = ast.parse(source)
    except SyntaxError as exc:
        return [f"unparseable: {exc}"]
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name.split(".")[0] in DANGEROUS_MODULES:
                    hits.append(f"line {node.lineno}: import {alias.name}")
        elif isinstance(node, ast.ImportFrom):
            if (node.module or "").split(".")[0] in DANGEROUS_MODULES:
                hits.append(f"line {node.lineno}: from {node.module} import ...")
        elif isinstance(node, ast.Call):
            name = _dotted(node.func) or ""
            short = name.split(".")[-1]
            for capability in FORBIDDEN_CAPABILITIES:
                names = CAPABILITY_CALLS[capability]
                if name in names or (capability == "filesystem" and name == "open") or (
                    capability == "dynamic_code" and short in {"eval", "exec", "compile"}
                ):
                    hits.append(f"line {node.lineno}: {capability} -> {name or short}")
                    break
    return hits


def assemble(functions: list[dict]) -> str:
    """Harness-owned boilerplate: `def` lines and indentation. Model-owned: the bodies."""
    parts = ['"""Sanitized loader. Bodies written by a local open-weight model, '
             'assembled and gated by Quarantine."""', ""]
    for fn in functions:
        name = str(fn.get("name", "")).strip()
        args = str(fn.get("args", "")).strip()
        if not name.isidentifier():
            continue
        body = [str(line) for line in (fn.get("body") or [])]
        if not body:
            body = ["pass"]
        parts.append(f"def {name}({args}):")
        parts.append("")
        for line in body:
            stripped = line.rstrip()
            parts.append(f"    {stripped.strip()}" if stripped.strip() else "")
        parts.append("")
    return "\n".join(parts).rstrip() + "\n"


def _extract(text: str) -> dict | None:
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass
    start, end = text.find("{"), text.rfind("}")
    if start != -1 and end > start:
        try:
            return json.loads(text[start:end + 1])
        except json.JSONDecodeError:
            pass
    return None


def synthesize_loader(declared: str, code: str, verdict: dict | None) -> dict:
    started = time.time()
    problem = ""
    if verdict:
        problem = (f"Verdict: {verdict.get('verdict')}. "
                   f"Mechanism: {verdict.get('mechanism', '')}")
    messages = [
        {"role": "system", "content": SYSTEM},
        {"role": "user", "content": (
            f"=== DECLARED BEHAVIOUR ===\n{declared.strip()[:1000]}\n\n"
            f"=== SHIPPED CODE (to repair) ===\n{code.strip()[:1500]}\n\n"
            f"=== WHY IT WAS BLOCKED ===\n{problem[:400]}\n\n"
            "Return the kept functions now.")},
    ]

    out: dict = {"model": resolve_model(llm.MODEL), "ok": False, "removed": [], "code": None,
                 "forbidden": [], "error": None, "attempts": [],
                 "assembled_by": "quarantine (def/indent) + model (bodies)"}

    # Through `llm.chat`, like every other model call. This file used to hold its own HTTP
    # client as well, which made the AI-usage disclosure's "one place that talks to the
    # model" inaccurate for the repairer too.
    for attempt in range(1, MAX_ATTEMPTS + 1):
        try:
            text, parsed = llm.chat(messages, schema=SCHEMA, max_tokens=600)
        except llm.ModelUnreachable as exc:
            out["error"] = str(exc)
            out["elapsed_s"] = round(time.time() - started, 2)
            return out
        _ = parsed

        candidate = _extract(text) or {}
        functions = candidate.get("functions") if isinstance(candidate.get("functions"), list) else None
        record = {"attempt": attempt, "got_functions": bool(functions)}

        if functions:
            source = assemble(functions)
            names = [f.get("name") for f in functions if isinstance(f, dict)]
            forbidden = forbidden_in_source(source)
            defines_api = "def generate" in source
            record.update({"functions": names, "forbidden": forbidden,
                           "defines_generate": defines_api})
            if not forbidden and defines_api:
                out.update({"ok": True, "code": source, "removed": candidate.get("removed", []),
                            "forbidden": [], "defines_generate": True})
                out["attempts"].append(record)
                out["elapsed_s"] = round(time.time() - started, 2)
                return out
            reason = ("forbidden capabilities remain: " + "; ".join(forbidden)) if forbidden \
                else "does not define generate()"
            out["code"] = source
            out["forbidden"] = forbidden
        else:
            reason = "the answer was not valid JSON with a functions list"

        record["reason"] = reason
        out["attempts"].append(record)
        out["error"] = reason

        if attempt < MAX_ATTEMPTS:
            messages = messages + [
                {"role": "assistant", "content": text[:1500]},
                {"role": "user", "content": (
                    f"REJECTED by the deterministic gate: {reason}\n"
                    "Return the JSON again. Keep the function named generate with argument "
                    "prompt, and put its body lines in the body array.")},
            ]

    out["elapsed_s"] = round(time.time() - started, 2)
    return out
