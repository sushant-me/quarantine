"""The contained execution environment.

Every flag here exists to make one sentence true: *the artifact runs where it
cannot reach anything that matters.* If you change this file, change the
sentence in the README too, because a receipt is only worth what the box is.
"""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

BASE_IMAGE = os.environ.get("QUARANTINE_BASE_IMAGE", "python:3.12-slim")
ANALYSIS_IMAGE = os.environ.get("QUARANTINE_ANALYSIS_IMAGE", "quarantine-analysis:latest")

_IMAGE_CACHE: list[str] = []


def _image_present(tag: str) -> bool:
    try:
        probe = subprocess.run(["docker", "image", "inspect", tag],
                               capture_output=True, timeout=20)
        return probe.returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


def resolve_image() -> str:
    """Which box to run the artifact in — and the answer is recorded in every receipt.

    **The base image is the default, and that is a measured decision, not an oversight.**

    The analysis image (torch + transformers) is built and kept, because without it a custom
    `modeling_*.py` cannot run at all and the case has to be escalated. But measuring it
    showed it is not a free win: it *raised* the false-positive rate on the Nepali/Indic
    controls from 0 to 2 of 5, and it broke legacy pickle reading that the stubs had handled
    (a real 328 MB `pytorch_model.bin` then failed with `AttributeError: 'NoneType' object
    has no attribute 'dtype'`, because the storages we stub are consumed for real).

    So it is opt-in, and the reason is in the receipt either way:

        QUARANTINE_IMAGE=quarantine-analysis:latest python -m quarantine.cli inspect ...

    Proper event attribution — knowing that a `dlopen` came from a library's import rather
    than from the artifact — is the work that would let it become the default. Until that
    exists, the honest thing is to ship the configuration that measures better.
    """
    if _IMAGE_CACHE:
        return _IMAGE_CACHE[0]
    explicit = os.environ.get("QUARANTINE_IMAGE")
    chosen = explicit or BASE_IMAGE
    _IMAGE_CACHE.append(chosen)
    return chosen


IMAGE = resolve_image()

# Hardening: no network, read-only root, no capabilities, no privilege gain,
# bounded processes/memory/cpu/time, and the artifact mounted read-only.
#
# Dropping ALL capabilities also removes CAP_DAC_OVERRIDE, so root inside the
# container cannot read files it does not own — a real hardening effect that
# broke the first run. The container therefore runs as the *invoking user*, which
# is also the better default: the artifact must be readable and the work
# directory writable by that same unprivileged identity.
DOCKER_FLAGS = [
    "--rm",
    "--network", "none",
    "--read-only",
    "--cap-drop", "ALL",
    "--security-opt", "no-new-privileges",
    "--user", f"{os.getuid()}:{os.getgid()}",
    "--workdir", "/work",
    "--pids-limit", "128",
    "--memory", "512m",
    "--cpus", "1",
    "--tmpfs", "/tmp:rw,size=64m",
]


def _runner_path() -> Path:
    return Path(__file__).resolve().parents[1] / "sandbox_runner.py"


def _docker(args: list[str], timeout: int) -> dict:
    try:
        proc = subprocess.run(["docker", *args], capture_output=True, text=True, timeout=timeout)
        return {"returncode": proc.returncode, "stdout": proc.stdout[-4000:], "stderr": proc.stderr[-2000:]}
    except FileNotFoundError:
        return {"returncode": None, "stdout": "", "stderr": "docker not found"}
    except subprocess.TimeoutExpired:
        return {"returncode": None, "stdout": "", "stderr": f"timeout after {timeout}s"}


def _base(artifact: Path, workdir: Path) -> list[str]:
    return [
        "run", *DOCKER_FLAGS,
        "-e", "PYTHONDONTWRITEBYTECODE=1",
        "-v", f"{artifact.resolve()}:/artifact:ro",
        "-v", f"{_runner_path()}:/harness/runner.py:ro",
        "-v", f"{workdir.resolve()}:/work:rw",
    ]


def run_baseline(workdir: Path, timeout: int = 180) -> dict:
    """Measure what this image does on its own, so it can be subtracted from a trace.

    Runs the same container with the same flags, importing the libraries the analysis image
    ships and nothing else. Whatever appears is the image's noise floor, not an artifact's
    behaviour — see `sandbox_runner.py::mode_baseline` for why that distinction is load-bearing.
    """
    workdir.mkdir(parents=True, exist_ok=True)
    cmd = _base(workdir / "empty", workdir) + [IMAGE, "python", "/harness/runner.py",
                                               "baseline", "/work/baseline.jsonl"]
    result = _docker(cmd, timeout)
    result["cmd"] = " ".join(cmd)
    result["image"] = IMAGE
    path = workdir / "baseline.jsonl"
    events = []
    if path.exists():
        for line in path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line:
                events.append(json.loads(line))
    result["events"] = events
    result["event_count"] = len(events)
    return result


def run_trace(artifact: Path, workdir: Path, timeout: int = 180) -> dict:
    """Execute the artifact's shipped code under the audit hook, network off."""
    workdir.mkdir(parents=True, exist_ok=True)
    cmd = _base(artifact, workdir) + [IMAGE, "python", "/harness/runner.py",
                                      "trace", "/artifact", "/work/trace.jsonl"]
    result = _docker(cmd, timeout)
    result["cmd"] = " ".join(cmd)
    trace_path = workdir / "trace.jsonl"
    events = []
    if trace_path.exists():
        for line in trace_path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line:
                events.append(json.loads(line))
    result["events"] = events
    result["event_count"] = len(events)
    exec_path = workdir / "exec.json"
    result["execution"] = json.loads(exec_path.read_text()) if exec_path.exists() else {}
    return result


def run_escape(workdir: Path, timeout: int = 180) -> dict:
    """Run the breakout probes inside the same box the artifacts get."""
    workdir.mkdir(parents=True, exist_ok=True)
    cmd = [
        "run", *DOCKER_FLAGS,
        "-e", "PYTHONDONTWRITEBYTECODE=1",
        "-v", f"{_runner_path()}:/harness/runner.py:ro",
        "-v", f"{workdir.resolve()}:/work:rw",
        IMAGE, "python", "/harness/runner.py", "escape", "/work/escape.json",
    ]
    result = _docker(cmd, timeout)
    result["cmd"] = " ".join(cmd)
    out_path = workdir / "escape.json"
    if out_path.exists():
        result.update(json.loads(out_path.read_text()))
    else:
        result.setdefault("probes", [])
        result["escaped"] = ["<no output: the container produced nothing>"]
    return result


def run_call(loader: Path, prompts: list[str], workdir: Path, timeout: int = 120) -> dict:
    """Import a single loader file and call generate() on fixed prompts."""
    workdir.mkdir(parents=True, exist_ok=True)
    (workdir / "prompts.json").write_text(json.dumps(prompts), encoding="utf-8")
    cmd = [
        "run", *DOCKER_FLAGS,
        "-e", "PYTHONDONTWRITEBYTECODE=1",
        "-v", f"{loader.resolve()}:/loader/loader.py:ro",
        "-v", f"{_runner_path()}:/harness/runner.py:ro",
        "-v", f"{workdir.resolve()}:/work:rw",
        IMAGE, "python", "/harness/runner.py", "call",
        "/loader/loader.py", "/work/prompts.json", "/work/out.json",
    ]
    result = _docker(cmd, timeout)
    result["cmd"] = " ".join(cmd)
    out_path = workdir / "out.json"
    result["result"] = (json.loads(out_path.read_text()) if out_path.exists()
                        else {"outputs": [], "error": "no output"})
    return result
