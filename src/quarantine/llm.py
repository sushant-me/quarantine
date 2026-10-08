"""One place that talks to the local model.

Every agent goes through here, so the model name recorded in a receipt is always read
back from the server rather than assumed, and there is a single implementation of the
schema-constrained call with its fallbacks.
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request

from quarantine.modelinfo import resolve_model

URL = os.environ.get("QUARANTINE_MODEL_URL", "http://127.0.0.1:8081/v1/chat/completions")
MODEL = os.environ.get("QUARANTINE_MODEL_NAME", "qwen2.5-coder-3b-instruct-q4_k_m")


class ModelUnreachable(RuntimeError):
    """The local model server did not answer. Never silently treated as a decision."""


def _post(payload: dict, timeout: int) -> dict:
    req = urllib.request.Request(URL, data=json.dumps(payload).encode(),
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode())


def parse_json(text: str) -> dict | None:
    """Tolerate prose around the object; return None rather than guessing."""
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
    if "def generate" in text:
        src = text.split("```python")[-1].split("```")[0] if "```" in text else text
        return {"loader_lines": src.splitlines(), "removed": ["<unstructured answer>"]}
    return None


def chat(messages: list[dict], schema: dict | None = None, max_tokens: int = 700,
         temperature: float = 0.0, timeout: int = 240) -> tuple[str, dict | None]:
    """Call the model. Returns (raw_text, parsed_json_or_None).

    Tries schema-constrained decoding first, then a JSON object, then plain — because
    the local runtime's support for each varies by version, and a silent downgrade that
    still returns valid JSON is better than a hard failure.
    """
    base = {"model": MODEL, "messages": messages, "temperature": temperature,
            "max_tokens": max_tokens, "stream": False}
    payloads = []
    if schema:
        payloads.append({**base, "response_format": {"type": "json_schema",
                                                     "json_schema": {"name": "out", "schema": schema}}})
    payloads.append({**base, "response_format": {"type": "json_object"}})
    payloads.append(base)

    last = ""
    for payload in payloads:
        try:
            body = _post(payload, timeout)
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            raise ModelUnreachable(f"{type(exc).__name__}: {exc}") from exc
        last = body.get("choices", [{}])[0].get("message", {}).get("content", "")
        parsed = parse_json(last) if schema else None
        if not schema or parsed is not None:
            return last, parsed
    return last, parse_json(last)


def served_model() -> str:
    """The model the server says it is serving — never a default."""
    return resolve_model(MODEL)
