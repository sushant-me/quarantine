"""Static pass — everything knowable about an artifact without running it.

This is the layer the incumbents live in. It is kept honest and separate so the
report can show exactly what static analysis does and does not see.
"""

from __future__ import annotations

import ast
import hashlib
import json
import re
import subprocess
import sys
import tempfile
from pathlib import Path

# capability -> dotted call names that imply it
CAPABILITY_CALLS: dict[str, set[str]] = {
    "network": {
        "socket.socket", "socket.create_connection", "socket.getaddrinfo",
        "socket.gethostbyname", "socket.gethostbyaddr", "socket.connect",
        "urllib.request.urlopen", "urllib.request.Request", "requests.get",
        "requests.post", "http.client.HTTPConnection", "ftplib.FTP",
        "smtplib.SMTP", "ssl.wrap_socket", "ssl.create_default_context",
    },
    "process": {
        "subprocess.Popen", "subprocess.run", "subprocess.call", "subprocess.check_output",
        "os.system", "os.popen", "os.execv", "os.execvp", "os.spawnv", "os.fork",
    },
    "dynamic_code": {
        "eval", "exec", "compile", "__import__", "importlib.import_module",
        "builtins.eval", "builtins.exec",
    },
    "filesystem": {
        "open", "os.remove", "os.unlink", "os.rename", "os.mkdir",
        "shutil.copyfile", "shutil.copy", "shutil.rmtree", "shutil.move",
    },
    "obfuscation": {
        "base64.b64decode", "base64.b64encode", "codecs.decode", "bytes.fromhex",
        "marshal.loads", "zlib.decompress", "binascii.unhexlify",
    },
    "deserialization": {
        "pickle.loads", "pickle.load", "dill.loads", "torch.load", "yaml.load",
    },
    "environment": {"os.getenv", "os.environ.get"},
}

SUSPICIOUS_MODULES = {
    "socket", "subprocess", "ctypes", "urllib", "http", "requests", "base64",
    "marshal", "pickle", "dill", "ssl", "ftplib", "smtplib", "pty",
    "multiprocessing", "shutil",
}

PICKLE_SUFFIXES = (".pkl", ".pickle", ".bin", ".pt", ".pth", ".ckpt", ".joblib")


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def inventory(root: Path) -> dict:
    """Every file, its size and its hash — the artifact's identity."""
    files = []
    for p in sorted(root.rglob("*")):
        if p.is_file():
            rel = str(p.relative_to(root))
            files.append({"path": rel, "size": p.stat().st_size, "sha256": sha256_file(p)})
    tree = hashlib.sha256(
        json.dumps([(f["path"], f["sha256"]) for f in files], sort_keys=True).encode()
    ).hexdigest()
    return {"files": files, "file_count": len(files), "tree_sha256": tree}


def _dotted(node: ast.AST) -> str | None:
    parts: list[str] = []
    cur = node
    while isinstance(cur, ast.Attribute):
        parts.append(cur.attr)
        cur = cur.value
    if isinstance(cur, ast.Name):
        parts.append(cur.id)
        return ".".join(reversed(parts))
    return None


def capability_graph(root: Path) -> dict:
    """Parse every shipped Python file and report what it is capable of.

    This is *capability*, not intent: `socket` imported is not an exfiltration.
    It is the map the semantic pass reasons over.
    """
    findings: list[dict] = []
    capabilities: dict[str, int] = {k: 0 for k in CAPABILITY_CALLS}
    imports: dict[str, list[str]] = {}
    py_files = sorted(root.rglob("*.py"))

    for path in py_files:
        rel = str(path.relative_to(root))
        try:
            tree = ast.parse(path.read_text(encoding="utf-8", errors="replace"))
        except SyntaxError as exc:
            findings.append({"file": rel, "line": exc.lineno or 0, "capability": "unparseable",
                             "detail": str(exc)})
            continue

        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    top = alias.name.split(".")[0]
                    if top in SUSPICIOUS_MODULES:
                        imports.setdefault(top, []).append(f"{rel}:{node.lineno}")
            elif isinstance(node, ast.ImportFrom):
                top = (node.module or "").split(".")[0]
                if top in SUSPICIOUS_MODULES:
                    imports.setdefault(top, []).append(f"{rel}:{node.lineno}")
            elif isinstance(node, ast.Call):
                name = _dotted(node.func) or ""
                short = name.split(".")[-1]
                for capability, names in CAPABILITY_CALLS.items():
                    if name in names or f"{name}" in names or (
                        capability == "filesystem" and name == "open"
                    ) or (capability == "dynamic_code" and short in {"eval", "exec", "compile"}):
                        findings.append({
                            "file": rel, "line": node.lineno,
                            "capability": capability, "call": name or short,
                        })
                        capabilities[capability] += 1
                        break

    return {
        "python_files": len(py_files),
        "imports_of_interest": imports,
        "capabilities": capabilities,
        "findings": findings,
    }


def _run(cmd: list[str], timeout: int = 300, cwd: str | None = None) -> dict:
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, cwd=cwd)
        return {"cmd": " ".join(cmd), "returncode": proc.returncode,
                "stdout": proc.stdout[-4000:], "stderr": proc.stderr[-2000:]}
    except FileNotFoundError as exc:
        return {"cmd": " ".join(cmd), "returncode": None, "stdout": "", "stderr": f"not found: {exc}"}
    except subprocess.TimeoutExpired:
        return {"cmd": " ".join(cmd), "returncode": None, "stdout": "", "stderr": "timeout"}


def run_incumbents(root: Path) -> dict:
    """What the tools a team already runs say about this artifact."""
    out: dict[str, dict] = {}
    out["picklescan"] = _run([sys.executable, "-m", "picklescan", "--path", str(root)])

    fickling_runs = []
    for p in sorted(root.rglob("*")):
        if p.is_file() and p.suffix.lower() in PICKLE_SUFFIXES:
            # fickling drops a `safety_results.json` in the current directory as a side
            # effect; run it from a scratch directory so it does not litter the repo.
            fickling_runs.append(_run([sys.executable, "-m", "fickling", "--check-safety", str(p)],
                                      cwd=tempfile.gettempdir()))
    out["fickling"] = fickling_runs or [{"cmd": "fickling", "returncode": None,
                                         "stdout": "", "stderr": "no pickle files found"}]
    return out


def _num(stdout: str, label: str) -> int | None:
    m = re.search(rf"{label}\s*:\s*(\d+)", stdout or "")
    return int(m.group(1)) if m else None


def parse_picklescan(run: dict) -> dict:
    """Read picklescan's own summary rather than guessing from words."""
    text = run.get("stdout") or ""
    scanned = _num(text, "Scanned files")
    infected = _num(text, "Infected files")
    suspicious = _num(text, "Suspicious globals")
    dangerous = _num(text, "Dangerous globals")
    clean = None
    if None not in (infected, suspicious, dangerous):
        clean = (infected == 0 and suspicious == 0 and dangerous == 0)
    return {"scanned_files": scanned, "infected": infected, "suspicious": suspicious,
            "dangerous": dangerous, "says_clean": clean}


def parse_fickling(runs: list[dict]) -> dict:
    """fickling --check-safety is silent and exits 0 when a pickle is safe."""
    scanned, flagged = 0, []
    for r in runs:
        text = (r.get("stdout") or "") + (r.get("stderr") or "")
        if "no pickle files found" in text:
            continue
        scanned += 1
        if any(k in text for k in ("DANGEROUS", "dangerous", "Warning:", "unsafe")):
            flagged.append({"cmd": r.get("cmd"), "output": text.strip()[:300]})
        elif r.get("returncode") not in (0, None):
            flagged.append({"cmd": r.get("cmd"), "output": f"exit {r.get('returncode')}"})
    return {"scanned_files": scanned, "flagged": flagged, "says_clean": not flagged}


def static_pass(root: Path) -> dict:
    inv = inventory(root)
    graph = capability_graph(root)
    incumbents = run_incumbents(root)
    custom = [f["path"] for f in inv["files"]
              if f["path"].startswith("custom_generate/") or f["path"].startswith("modeling_")]

    ps = parse_picklescan(incumbents["picklescan"])
    fk = parse_fickling(incumbents["fickling"])
    incumbents["picklescan_parsed"] = ps
    incumbents["fickling_parsed"] = fk

    return {
        "inventory": inv,
        "capability_graph": graph,
        "incumbents": incumbents,
        "incumbent_verdict": {
            "picklescan": ps,
            "fickling": fk,
            "scanned_custom_python": False,
            "shipped_python_files": custom,
            "note": ("Suffix-based scanners read pickle/weight files. Shipped Python "
                     "(custom_generate/, modeling_*.py) is not in their input set at all, "
                     "so an artifact can be 'clean' to every scanner and still execute "
                     "arbitrary code on load."),
        },
        "custom_code_files": custom,
    }
