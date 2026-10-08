"""Which model actually answered?

A receipt that names the wrong model is worse than no receipt: it is a false
record. The model name is therefore read back from the server that served the
request, never assumed from a default.
"""

from __future__ import annotations

import json
import os
import urllib.request

DEFAULT_URL = "http://127.0.0.1:8081/v1/chat/completions"


def model_url() -> str:
    return os.environ.get("QUARANTINE_MODEL_URL", DEFAULT_URL)


def models_endpoint() -> str:
    base = model_url()
    for suffix in ("/chat/completions", "/completions"):
        if base.endswith(suffix):
            base = base[: -len(suffix)]
            break
    return base.rstrip("/") + "/models"


def resolve_model(fallback: str) -> str:
    """Ask the server what it is serving; fall back only if it cannot say.

    llama.cpp reports the loaded weights under `name`/`model` (a path), OpenAI-style
    servers use `id`. Accept any of them, and reduce a path to its basename so the
    receipt records something a human can check.
    """
    try:
        with urllib.request.urlopen(models_endpoint(), timeout=10) as resp:
            data = json.loads(resp.read().decode())
        for entry in data.get("data", []) or data.get("models", []):
            for key in ("id", "name", "model"):
                value = entry.get(key)
                if value:
                    return os.path.basename(str(value))
    except Exception:
        pass
    return fallback
