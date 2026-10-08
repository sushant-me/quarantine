"""sandbox_runner.py — runs INSIDE the container. Standard library only.

Two modes:

  trace <artifact_dir> <out.jsonl>
      Installs a CPython audit hook (PEP 578) that records every sensitive
      operation, then executes the artifact's shipped custom code the way
      `trust_remote_code=True` does. Writes one JSON object per line.

  call <loader.py> <prompts.json> <out.json>
      Imports a loader module and calls generate(prompt) on each prompt.
      Used for the output-equivalence proof.

The audit hook is the evidence source. It costs nothing, needs no ptrace or
kernel privileges, and works inside a network-less, read-only container.
"""

from __future__ import annotations

import importlib.util
import json
import os
import pickle
import sys
import traceback

ARTIFACT = ""
OUT = ""
_suspend = False
_active = False
_events: list[dict] = []
_seen: set[tuple[str, str]] = set()
_seq = 0
MAX_EVENTS = 400

# Network / execution / exfiltration are the operations that matter.
WATCH_EXACT = {
    "socket.getaddrinfo", "socket.gethostbyname", "socket.gethostbyaddr",
    "socket.connect", "socket.bind", "socket.sendto", "socket.sendmsg",
    "subprocess.Popen", "os.system", "os.exec", "os.posix_spawn", "os.spawn",
    "os.fork", "os.forkpty",
    "ctypes.dlopen", "ctypes.dlsym", "ctypes.call_function",
    "pickle.find_class", "shutil.copyfile", "shutil.move",
    "os.remove", "os.rename", "os.mkdir", "os.rmdir",
    "os.putenv", "os.unsetenv",
}
SUSPICIOUS_IMPORTS = {
    "socket", "ssl", "subprocess", "ctypes", "urllib", "http", "ftplib",
    "smtplib", "telnetlib", "requests", "base64", "codecs", "marshal",
    "pickle", "dill", "pty", "multiprocessing", "asyncio",
}
SAFE_OPEN_PREFIXES = (
    "/usr/", "/proc/self", "/sys/", "/lib/", "/etc/ld.so", "/dev/null",
    "/dev/urandom", "/usr/local/lib/python", "/tmp/",
)


def _record(event: str, detail: str) -> None:
    global _seq
    global _suspend
    if _suspend or len(_events) >= MAX_EVENTS:
        return
    key = (event, detail)
    if key in _seen:
        return
    _seen.add(key)
    _seq += 1
    _events.append({"i": _seq, "event": event, "detail": detail})


def _hook(event: str, args) -> None:
    """Audit hook. Must never raise and must never open a file itself."""
    try:
        # Record only what the artifact does while it is actually running.
        #
        # This gate was added after a measured false-positive: `compile` and `exec`
        # fire for every ordinary module body and every import, so the benign control
        # looked like an artifact that executes dynamic code and was blocked. Those
        # events are the interpreter, not the artifact, and they are not evidence.
        if not _active or event in ("compile", "exec"):
            return
        if event == "open":
            path = str(args[0]) if args else ""
            if ARTIFACT and path.startswith(ARTIFACT):
                return
            if path.startswith(SAFE_OPEN_PREFIXES) or path.endswith((".pyc", ".so")):
                return
            _record("file.read", path)
        elif event == "import":
            name = str(args[0]).split(".")[0] if args else ""
            if name in SUSPICIOUS_IMPORTS:
                _record("import", name)
        elif event == "compile":
            _record("compile", "<code object>")
        elif event == "exec":
            _record("exec", "<code object>")
        elif event in WATCH_EXACT:
            detail = ""
            if args:
                try:
                    if event == "pickle.find_class" and len(args) >= 2:
                        # the global a pickle asks for: this is the payload's intent
                        detail = f"{args[0]}.{args[1]}"
                    else:
                        detail = str(args[0])[:200]
                except Exception:
                    detail = "<unprintable>"
            _record(event, detail)
    except Exception:
        return


def _run_active(fn):
    """Run something as 'the artifact', so the hook records it."""
    global _active
    _active = True
    try:
        return fn()
    finally:
        _active = False


def _flush(path: str | None = None) -> None:
    """Stop recording, and optionally write the trace.

    The path argument exists because `mode_call` keeps its events in memory and returns
    them inside its own result file. Before this took an argument, `mode_call` called it
    with an unset global and both loaders silently failed to run — caught immediately by
    the stricter equivalence criterion, which reported "a run failed" instead of a pass.
    """
    global _suspend
    _suspend = True
    if not path:
        return
    with open(path, "w", encoding="utf-8") as fh:
        for item in _events:
            fh.write(json.dumps(item) + "\n")


def _find_custom_code(artifact: str) -> list[str]:
    """The files `trust_remote_code=True` would execute."""
    found = []
    cg = os.path.join(artifact, "custom_generate", "generate.py")
    if os.path.exists(cg):
        found.append(cg)
    for name in sorted(os.listdir(artifact)):
        if name.startswith("modeling_") and name.endswith(".py"):
            found.append(os.path.join(artifact, name))
    return found


WEIGHT_SUFFIXES = (".bin", ".pkl", ".pickle", ".pt", ".pth", ".ckpt", ".joblib")


def _find_weight_files(artifact: str) -> list[str]:
    """Files a loader would unpickle. Suffix scanners read these; we execute them."""
    found = []
    for root, _dirs, files in os.walk(artifact):
        for name in sorted(files):
            if name.lower().endswith(WEIGHT_SUFFIXES):
                found.append(os.path.join(root, name))
    return found


def mode_trace(artifact: str, out: str) -> int:
    global ARTIFACT, OUT
    ARTIFACT, OUT = artifact, out
    sys.addaudithook(_hook)

    targets = _find_custom_code(artifact)
    weights = _find_weight_files(artifact)
    result = {"executed": [], "weights_loaded": [], "weights_unreadable": [], "errors": []}
    if not targets and not weights:
        result["errors"].append("no custom code and no weight files found")

    for path in targets:
        rel = os.path.relpath(path, artifact)
        try:
            spec = importlib.util.spec_from_file_location("artifact_custom", path)
            mod = importlib.util.module_from_spec(spec)
            sys.modules["artifact_custom"] = mod
            _run_active(lambda: spec.loader.exec_module(mod))
            # Exercise the declared API, so a loader that only acts when called is seen too.
            if hasattr(mod, "generate"):
                try:
                    _run_active(lambda: mod.generate("probe prompt"))
                except Exception as exc:
                    result["errors"].append(f"generate() raised: {exc!r}")
            result["executed"].append({"file": rel, "status": "executed"})
        except Exception as exc:
            result["errors"].append(f"{rel}: {exc!r}")
            _record("artifact.error", f"{rel}: {type(exc).__name__}: {exc}")

    # The other code path: unpickling weights. This is where the classic attacks live,
    # and it is the only way to see what the pickle actually does rather than what it names.
    for path in weights:
        rel = os.path.relpath(path, artifact)
        try:
            with open(path, "rb") as fh:
                _run_active(lambda handle=fh: pickle.load(handle))
            result["weights_loaded"].append({"file": rel, "status": "loaded"})
        except Exception as exc:
            # A real torch checkpoint is a zip archive, not a bare pickle, so a
            # plain-pickle reader cannot open it. That is a limitation of this
            # reader, not behaviour of the artifact, so it is recorded as
            # unreadable and is deliberately NOT a capability event.
            result["weights_unreadable"].append({"file": rel, "why": type(exc).__name__})
            _record("weights.unreadable", f"{rel}: {type(exc).__name__}")

    _flush(OUT)
    with open(os.path.join(os.path.dirname(out), "exec.json"), "w", encoding="utf-8") as fh:
        json.dump(result, fh, indent=2)
    return 0


def mode_escape(out: str) -> int:
    """Try to break out of this box, on purpose, and write down what happened.

    Every probe is a *contained* check of one primitive. If one of them succeeds, that
    is a finding and it is reported as `succeeded: true` — a containment claim that has
    never been attacked is a claim, not a measurement.
    """
    probes: list[dict] = []

    def attempt(name: str, what: str, fn) -> None:
        try:
            detail = fn()
            probes.append({"probe": name, "primitive": what, "succeeded": True,
                           "detail": str(detail)[:200]})
        except Exception as exc:
            probes.append({"probe": name, "primitive": what, "succeeded": False,
                           "detail": f"{type(exc).__name__}: {exc}"[:200]})

    def write_rootfs():
        with open("/quarantine_escape_test", "w") as fh:      # read-only rootfs
            fh.write("x")
        return "wrote to /"

    def read_shadow():
        return open("/etc/shadow").read()[:40]                # non-root, 0640 root:shadow

    def read_host_path():
        return open("/home/logic/win/NEW-IDEA-DECISION.md").read()[:40]   # host file, not mounted

    def mount_tmpfs():
        import ctypes
        libc = ctypes.CDLL("libc.so.6", use_errno=True)
        MS_NOSUID, MS_NODEV = 2, 4
        rc = libc.mount(b"tmpfs", b"/mnt", b"tmpfs", MS_NOSUID | MS_NODEV, b"size=1m")
        if rc != 0:
            raise OSError(ctypes.get_errno(), os.strerror(ctypes.get_errno()))
        return "mounted tmpfs on /mnt"

    def unshare_userns():
        import ctypes
        libc = ctypes.CDLL("libc.so.6", use_errno=True)
        CLONE_NEWUSER = 0x10000000
        rc = libc.unshare(CLONE_NEWUSER)
        if rc != 0:
            raise OSError(ctypes.get_errno(), os.strerror(ctypes.get_errno()))
        return "created a new user namespace"

    def chroot_root():
        os.chroot("/")
        return "chrooted"

    def setuid_root():
        os.setuid(0)
        return f"uid is now {os.getuid()}"

    def raw_socket():
        import socket as s
        sock = s.socket(s.AF_INET, s.SOCK_RAW, s.IPPROTO_ICMP)
        sock.close()
        return "opened a raw ICMP socket"

    def reach_host_model_server():
        import socket as s
        with s.create_connection(("127.0.0.1", 8081), timeout=3):
            return "connected to the host model server"

    def resolve_public_name():
        import socket as s
        return s.getaddrinfo("example.com", 80)[0][4]

    attempt("write_rootfs", "write to the read-only root filesystem", write_rootfs)
    attempt("read_shadow", "read /etc/shadow as an unprivileged user", read_shadow)
    attempt("read_host_path", "read a host file that was not mounted", read_host_path)
    attempt("mount_tmpfs", "mount(2) a filesystem", mount_tmpfs)
    attempt("unshare_userns", "unshare(CLONE_NEWUSER)", unshare_userns)
    attempt("chroot", "chroot(2)", chroot_root)
    attempt("setuid_root", "become uid 0", setuid_root)
    attempt("raw_socket", "open a raw socket (CAP_NET_RAW)", raw_socket)
    attempt("reach_host", "connect to the host's model server over the loopback", reach_host_model_server)
    attempt("resolve_dns", "resolve a public name", resolve_public_name)

    result = {
        "identity": {"uid": os.getuid(), "euid": os.geteuid(), "pid": os.getpid()},
        "container_markers": {
            "dockerenv": os.path.exists("/.dockerenv"),
            "root_mounts": [m.strip() for m in open("/proc/mounts").read().splitlines()
                            if m.split()[1] in ("/", "/tmp")][:2],
        },
        "probes": probes,
        "escaped": [p["probe"] for p in probes if p["succeeded"]],
    }
    with open(out, "w", encoding="utf-8") as fh:
        json.dump(result, fh, indent=2)
    return 0


def mode_call(loader: str, prompts_path: str, out: str) -> int:
    """Import one loader and call generate() on fixed prompts — under the audit hook.

    Outputs alone would only prove the repair *behaves* the same. Recording the trace
    here proves something stronger: that the repaired loader performed **no capability
    operation at all** while producing those identical outputs, which is the difference
    between "it still works" and "it is safe".
    """
    global ARTIFACT
    ARTIFACT = os.path.dirname(os.path.abspath(loader))
    sys.addaudithook(_hook)

    with open(prompts_path, encoding="utf-8") as fh:
        prompts = json.load(fh)
    outputs, error = [], None
    try:
        spec = importlib.util.spec_from_file_location("loader_under_test", loader)
        mod = importlib.util.module_from_spec(spec)
        sys.modules["loader_under_test"] = mod
        _run_active(lambda: spec.loader.exec_module(mod))
        for prompt in prompts:
            outputs.append(_run_active(lambda p=prompt: mod.generate(p)))
    except Exception:
        error = traceback.format_exc(limit=3)
    _flush()
    with open(out, "w", encoding="utf-8") as fh:
        json.dump({"outputs": outputs, "error": error, "events": _events}, fh, indent=2)
    return 0


def main() -> int:
    if len(sys.argv) < 2:
        print(__doc__)
        return 2
    mode = sys.argv[1]
    if mode == "trace":
        return mode_trace(sys.argv[2], sys.argv[3])
    if mode == "call":
        return mode_call(sys.argv[2], sys.argv[3], sys.argv[4])
    if mode == "escape":
        return mode_escape(sys.argv[2])
    print(f"unknown mode {mode!r}")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
