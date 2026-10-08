"""What counts as evidence of behaviour.

One definition, used by the semantic pass to decide whether an answer is admissible,
and by the challenger and supervisor to decide whether a case is decidable at all.

It is deliberately narrow: an event is evidence of capability only if the artifact
performed an operation that a pure text transform has no reason to perform.

Note what is NOT here:

* `import`, `compile`, `exec` and the harness's own bookkeeping — recording those
  produced a measured false positive, because importing a stdlib module looked like
  dynamic code execution;
* a `pickle.find_class` for **anything but an unambiguous execution or I/O primitive**.

That second rule took two attempts to get right, and both were caught by controls rather
than by a hand-written case. Once the reader learned to open torch's zip format, every
legitimate checkpoint started asking for `collections.OrderedDict`,
`torch._utils._rebuild_tensor_v2` and `torch.LongStorage` — so scaffolding was filtered
out. Then a control group of *benign* standard-library calls (`json.dumps`, `math.sqrt`,
`re.compile`, `os.getcwd`) showed that we were still counting **every** requested global
as evidence, which would flag an ordinary pickle for asking for `json`.

The rule now: **asking for a global is intent, not capability.** It is evidence only when
the global is an unambiguous way to execute code or touch the machine (`eval`, `exec`,
`open`, `system`, `Popen`, `urlopen`, `dlopen`, …). Everything else — including the whole
tensor-rebuild and scaffolding surface — is context that the analyst can read in the
trace, not something the deterministic gate counts. Capability means it **happened**.
"""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

CAPABILITY_EVENTS = {
    # network
    "socket.getaddrinfo", "socket.gethostbyname", "socket.gethostbyaddr",
    "socket.connect", "socket.bind", "socket.sendto", "socket.sendmsg",
    "urllib.Request", "http.client.connect",
    # process
    "subprocess.Popen", "os.system", "os.exec", "os.posix_spawn", "os.spawn",
    "os.fork", "os.forkpty",
    # filesystem, outside the artifact's own directory
    "file.read",
    # deserialization intent — filtered, see below
    "pickle.find_class",
    # native
    "ctypes.dlopen", "ctypes.dlsym", "ctypes.call_function",
    # mutation of the host
    "shutil.copyfile", "shutil.move", "os.remove", "os.rename", "os.mkdir", "os.rmdir",
    "os.putenv", "os.unsetenv",
}

# Unambiguous builtins: asking a pickle for one of these is intent worth reporting.
# Matched only in the `builtins` module (plus `_io.open`, which is how a pickle refers to
# `open`) — `re.compile` is a different function that happens to share a name.
#
# `getattr`/`setattr`/`delattr` are deliberately NOT here: the pickle protocol itself emits
# `builtins.getattr` to reference a method (it is how `datetime.now` is serialised), so
# treating it as evidence flagged a harmless control. Any real use of it to reach a
# dangerous callable still fires that callable's own event.
DANGEROUS_BUILTINS = {
    "eval", "exec", "compile", "__import__", "open", "input", "breakpoint",
    "vars", "globals", "locals",
}

# Globals that are themselves a way to execute code or touch the machine, whatever module
# they come from. A `pickle.find_class` for one of these is evidence; for anything else it
# is context. The tensor-rebuild and serialization scaffolding is deliberately absent.
DANGEROUS_GLOBALS = {
    "system", "popen", "spawn", "spawnl", "spawnle", "spawnlp", "spawnv", "spawnve",
    "posix_spawn", "fork", "forkpty", "Popen", "call", "check_call", "check_output", "run",
    "dlopen", "dlsym", "dlmopen",
    "urlopen", "urlretrieve", "HTTPConnection", "HTTPSConnection", "ServerProxy",
    "FTP", "FTP_TLS", "SMTP", "SMTP_SSL", "POP3", "POP3_SSL", "IMAP4", "IMAP4_SSL",
    "NNTP", "Telnet", "socket", "create_connection", "create_server", "connect",
    "getaddrinfo", "gethostbyname", "gethostbyaddr", "getfqdn", "get_server_certificate",
    "wrap_socket",
    "rmtree", "remove", "unlink", "rename", "replace", "chmod", "chown", "mkdir",
    "makedirs", "chdir", "symlink", "copyfile", "copytree", "move", "copy",
}

# A recursive load: the name is generic, so it only counts inside a loader module.
_LOADER_MODULES = {"pickle", "dill", "joblib", "torch", "cloudpickle", "marshal"}


def _find_class_is_evidence(detail: str) -> bool:
    module, _, name = detail.rpartition(".")
    if not module or not name:
        return True
    if module == "builtins":
        return name in DANGEROUS_BUILTINS
    if module == "_io" and name == "open":
        return True
    if name in DANGEROUS_GLOBALS:
        return True
    if name in {"load", "loads"} and module.split(".")[0] in _LOADER_MODULES:
        return True
    return False


def noise_key(event: str, detail: object) -> tuple[str, str]:
    """A stable key for "this event, regardless of the random name in it".

    `/tmp/torchinductor_uid_1000` and `/tmp/fleig390` are different strings and the same
    kind of thing: something the interpreter or a library did to a temporary path.
    """
    text = re.sub(r"\d+", "#", str(detail))
    text = re.sub(r"/tmp/[^/\s]+", "/tmp/#", text)
    return (event, text)


def baseline_path(image: str | None = None) -> Path:
    """Where the measured noise floor for an image lives."""
    if image is None:
        from quarantine.sandbox.execute import IMAGE
        image = IMAGE
    slug = re.sub(r"[^A-Za-z0-9._-]", "_", image)
    return Path(__file__).resolve().parents[2] / "baselines" / f"{slug}.jsonl"


_BASELINE_CACHE: dict[str, set] = {}


def baseline_keys(path: Path | None = None) -> set:
    """The measured noise floor, as keys. Empty when none has been measured."""
    path = path or baseline_path()
    cache_key = str(path)
    if cache_key in _BASELINE_CACHE:
        return _BASELINE_CACHE[cache_key]
    keys: set = set()
    if path.exists():
        for line in path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                event = json.loads(line)
                keys.add(noise_key(event["event"], event.get("detail", "")))
            except (json.JSONDecodeError, KeyError):
                continue
    _BASELINE_CACHE[cache_key] = keys
    return keys


def baseline_info(image: str | None = None) -> dict:
    """Provenance for the receipt: was a noise floor applied, and which one."""
    path = baseline_path(image)
    if not path.exists():
        return {"applied": False, "note": "no noise floor measured for this image"}
    keys = baseline_keys(path)
    return {
        "applied": True,
        "file": path.name,
        "keys": len(keys),
        "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
        "note": ("events this image produces by importing its own libraries are not "
                 "evidence of the artifact's behaviour"),
    }


def capability_events(events: list[dict]) -> list[dict]:
    """The subset of a trace that is evidence of capability rather than context."""
    floor = baseline_keys()
    out = []
    for event in events:
        name = event.get("event")
        if name not in CAPABILITY_EVENTS:
            continue
        if name == "pickle.find_class" and not _find_class_is_evidence(event.get("detail", "")):
            continue
        if floor and noise_key(name, event.get("detail", "")) in floor:
            continue
        out.append(event)
    return out
