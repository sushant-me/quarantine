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
import io
import json
import os
import pickle
import sys
import traceback
import zipfile

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
    # The harness's own files. A payload that makes a library read *our* source is not doing
    # anything to the artifact — it showed up as `file.read /harness/runner.py` on several
    # samples of picklescan's corpus, where the payload only asked for `inspect`/`linecache`
    # behaviour, and it was being counted as evidence of capability.
    "/harness/",
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


WEIGHT_SUFFIXES = (".bin", ".pkl", ".pickle", ".pt", ".pth", ".ckpt", ".joblib",
                   ".safetensors", ".gguf")

# Tensor serialization helpers. A torch checkpoint's `data.pkl` rebuilds tensors through
# these; with torch absent the lookup fails and the whole unpickling aborts, which is why
# real checkpoints used to be unreadable here.
#
# They are stubbed ONLY when they cannot be imported, and ONLY by exact (module, name),
# never by module. They construct tensors and cannot themselves reach the network or the
# filesystem. Everything else - ssl, socket, os, subprocess, builtins - resolves for real,
# because the payload has to actually run for us to see what it does.
TENSOR_HELPERS = {
    ("torch._utils", "_rebuild_tensor_v2"), ("torch._utils", "_rebuild_tensor"),
    ("torch._utils", "_rebuild_parameter"), ("torch._utils", "_rebuild_parameter_with_state"),
    ("torch._utils", "_rebuild_sparse_tensor"), ("torch._utils", "_rebuild_meta_tensor_no_storage"),
    ("torch._utils", "_rebuild_wrapper_subclass"), ("torch._utils", "_rebuild_device_tensor_from_numpy"),
    ("torch._utils", "_rebuild_qtensor"), ("torch._utils", "_rebuild_from_type_v2"),
    ("torch._utils", "_rebuild_from_type_v3"), ("torch._utils", "_rebuild_typed_storage"),
    ("torch._utils", "_rebuild_tensor_v3"), ("torch._utils", "_rebuild_batched_tensor"),
    ("torch.storage", "_load_from_bytes"), ("torch.storage", "_TypedStorage"),
    ("torch.storage", "UntypedStorage"), ("torch.serialization", "_get_restore_location"),
    ("torch", "Tensor"), ("torch", "Size"), ("torch", "device"), ("torch", "dtype"),
    ("torch", "float32"), ("torch", "float16"), ("torch", "uint8"), ("torch", "int64"),
    ("torch.nn.parameter", "Parameter"),
    ("numpy.core.multiarray", "_reconstruct"), ("numpy.core.multiarray", "scalar"),
    ("numpy.core.numeric", "_frombuffer"), ("numpy", "ndarray"), ("numpy", "dtype"),
    ("numpy", "uint8"), ("numpy", "float32"), ("numpy", "int64"),
}


def is_serialization_helper(module: str, name: str) -> bool:
    """Is this global part of *serialization machinery* rather than an operation?

    Used in two places, and both matter: this stub decision, and whether a
    `pickle.find_class` counts as evidence of capability. A legitimate torch checkpoint
    asks for `collections.OrderedDict`, `torch._utils._rebuild_tensor_v2` and
    `torch.LongStorage`; treating those as suspicious would flag every real model.

    The rule is structural and deliberately narrow: the torch serialization machinery,
    numpy's array reconstruction, and the pickle scaffolding in the standard library.
    `ssl`, `socket`, `os` and `subprocess` are never matched, and the dangerous builtins
    (`eval`, `exec`, `open`, `__import__`) are excluded explicitly.
    """
    if (module, name) in TENSOR_HELPERS:
        return True
    torch_module = module == "torch" or module.startswith("torch.")
    if torch_module and (name.endswith("Storage") or name.startswith("_rebuild")):
        return True
    numpy_module = module == "numpy" or module.startswith("numpy.")
    if numpy_module and name in {"ndarray", "dtype", "scalar", "_reconstruct", "_frombuffer"}:
        return True
    if module in {"collections", "copyreg", "types"}:
        return True
    return False


def _stub_helper(module: str, name: str):
    def _stub(*args, **kwargs):
        return None

    _stub.__name__ = name
    _stub.__qualname__ = f"{module}.{name}"
    return _stub


class AuditUnpickler(pickle.Unpickler):
    """Unpickle a torch `data.pkl` (or a plain pickle) and record what it asks for.

    A global that cannot be resolved and is not a known tensor helper is recorded as
    UNRESOLVED and the load aborts, because the artifact's behaviour was not faithfully
    reproduced — better to escalate than to judge a partial run.
    """

    def __init__(self, fh, notes: list[dict]) -> None:
        super().__init__(fh)
        self.notes = notes

    def find_class(self, module: str, name: str):
        try:
            return super().find_class(module, name)
        except Exception as exc:
            if is_serialization_helper(module, name):
                self.notes.append({"event": "stubbed", "global": f"{module}.{name}"})
                return _stub_helper(module, name)
            self.notes.append({"event": "unresolved", "global": f"{module}.{name}",
                               "why": f"{type(exc).__name__}: {exc}"})
            raise

    def persistent_load(self, pid):
        # Storage references resolve out of band in torch; there is nothing to load here.
        return None


def load_safetensors(path: str, notes: list[dict]) -> tuple[object, str]:
    """Validate a safetensors container — a format that cannot execute code by design.

    Layout: 8-byte little-endian header length, that many bytes of JSON, then tensor data.
    There is no pickle and no callable anywhere in it, so "we examined it and nothing can
    run" is a conclusion the format itself supports rather than one we are guessing at.

    Two honest limits, recorded here because they are easy to forget at the call site:
    we validate the *container and index*, not the tensor values — so a poisoned-weights
    attack is out of scope for this tool (see `LIMITATIONS.md`). And a file that merely
    claims the suffix but is not a valid container is rejected, which sends it down the
    escalation path rather than being quietly trusted.
    """
    import struct

    with open(path, "rb") as fh:
        raw = fh.read(8)
        if len(raw) != 8:
            raise ValueError("too short to be a safetensors header")
        (header_len,) = struct.unpack("<Q", raw)
        if header_len == 0 or header_len > 100 * 1024 * 1024:
            raise ValueError(f"implausible header length {header_len}")
        blob = fh.read(header_len)
        if len(blob) != header_len:
            raise ValueError(f"truncated header ({len(blob)} of {header_len} bytes)")

    index = json.loads(blob.decode("utf-8"))
    if not isinstance(index, dict) or not index:
        raise ValueError("header is not a non-empty JSON object")
    tensors = {k: v for k, v in index.items() if k != "__metadata__" and isinstance(v, dict)}
    malformed = [k for k, v in tensors.items() if "dtype" not in v or "shape" not in v]
    if malformed:
        raise ValueError(f"{len(malformed)} index entries are not tensor descriptors")
    notes.append({"event": "safetensors", "global": f"{len(tensors)} tensors indexed",
                  "why": f"header {header_len} bytes, valid container"})
    return index, "safetensors"


GGUF_MAGIC = b"GGUF"


def load_gguf(path: str, notes: list[dict]) -> tuple[object, str]:
    """Validate a GGUF container — a format with no pickle and no callable in it.

    GGUF is how the Nepali ecosystem mostly ships models (and a great deal of the wider
    open-weight world): `mradermacher` alone republishes almost everything as GGUF
    quantisations. Layout: magic `GGUF`, uint32 version, uint64 tensor count, uint64
    metadata count, then length-prefixed key/value metadata, then tensor descriptors, then
    tensor data. There is nothing executable anywhere in it.

    We validate the header and the metadata framing, not the tensor values — the same
    limit as `safetensors`, and the same honest scope: this is a code-execution question,
    not a poisoned-weights question (`LIMITATIONS.md` item 15). A pickle renamed `.gguf`
    fails the magic check and is escalated, never trusted.
    """
    import struct

    with open(path, "rb") as fh:
        head = fh.read(24)
        if len(head) < 24:
            raise ValueError("too short to be a GGUF header")
        if head[:4] != GGUF_MAGIC:
            raise ValueError(f"bad magic {head[:4]!r}: not a GGUF container")
        version, tensor_count, kv_count = struct.unpack("<IQQ", head[4:24])
        if version not in (2, 3):
            raise ValueError(f"unsupported GGUF version {version}")
        if not 0 < tensor_count < 10_000_000:
            raise ValueError(f"implausible tensor count {tensor_count}")
        if not 0 < kv_count < 100_000:
            raise ValueError(f"implausible metadata count {kv_count}")
        raw = fh.read(8)
        if len(raw) < 8:
            raise ValueError("truncated metadata")
        (key_len,) = struct.unpack("<Q", raw)
        if not 0 < key_len < 4096:
            raise ValueError(f"implausible metadata key length {key_len}")
        key = fh.read(key_len)
        if len(key) != key_len:
            raise ValueError("truncated metadata key")
        try:
            key.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ValueError(f"metadata key is not UTF-8: {exc}") from exc

    notes.append({"event": "gguf", "global": f"{tensor_count} tensors, {kv_count} metadata entries",
                  "why": f"GGUF v{version}, valid container"})
    return {"format": "gguf", "version": version, "tensor_count": tensor_count}, "gguf"


def load_weights(path: str, notes: list[dict]) -> tuple[object, str]:
    """Open a weight file in whatever form it actually ships.

    Four real formats, three different questions. `safetensors` and `gguf` containers are
    *validated*, because neither has a pickle or a callable in it. A zip checkpoint has its
    embedded pickle *executed* under the audit hook, because that is what `torch.load`
    would do. A plain pickle is loaded the same way.
    """
    if path.lower().endswith(".safetensors"):
        return load_safetensors(path, notes)
    if path.lower().endswith(".gguf"):
        return load_gguf(path, notes)
    with open(path, "rb") as fh:
        magic = fh.read(2)
    if magic == b"PK":                                   # zip: the modern torch format
        with zipfile.ZipFile(path) as zf:
            member = next((n for n in zf.namelist() if n.endswith("data.pkl")), None)
            if member is None:
                raise ValueError(f"zip archive with no data.pkl ({len(zf.namelist())} members)")
            blob = zf.read(member)
        return AuditUnpickler(io.BytesIO(blob), notes).load(), f"zip:{member}"
    with open(path, "rb") as fh:
        return AuditUnpickler(fh, notes).load(), "plain-pickle"


def _find_weight_files(artifact: str) -> list[str]:
    """Files a loader would unpickle. Suffix scanners read these; we execute them."""
    found = []
    for root, _dirs, files in os.walk(artifact):
        for name in sorted(files):
            if name.lower().endswith(WEIGHT_SUFFIXES):
                found.append(os.path.join(root, name))
    return found


BASELINE_MODULES = ("torch", "transformers", "numpy", "safetensors", "sentencepiece")


def mode_baseline(out: str) -> int:
    """Record the events this image produces **on its own**, by importing its libraries.

    Why this exists. Once the analysis image ships torch and transformers, an artifact that
    merely *references* them — an ordinary `pytorch_model.bin` whose pickle asks for
    `torch._utils._rebuild_tensor_v2` — causes torch to be imported, and torch's own import
    does `ctypes.dlopen` of its native libraries, sets and unsets its own environment
    variables, and runs its cache setup. On a plain benign control that produced five
    "capability events" and would have made every real model a false positive.

    Those events really happen; they are simply not the *artifact's* behaviour. So instead of
    guessing which events to ignore, we measure the noise floor of the image and subtract it.
    """
    global OUT
    OUT = out
    sys.addaudithook(_hook)

    def _import_all() -> None:
        for name in BASELINE_MODULES:
            try:
                importlib.import_module(name)
            except Exception:                          # noqa: BLE001 - absence is fine
                pass

    _run_active(_import_all)
    _flush(out)
    return 0


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
        notes: list[dict] = []
        try:
            _loaded = _run_active(lambda: load_weights(path, notes))
            how = _loaded[1] if isinstance(_loaded, tuple) else "unknown"
            result["weights_loaded"].append({"file": rel, "status": "loaded", "how": how})
            for note in notes:
                _record(f"weights.{note['event']}",
                        note["global"] + (f" ({note['why']})" if note.get("why") else ""))
        except Exception as exc:
            unresolved = [n["global"] for n in notes if n["event"] == "unresolved"]
            detail = f"{rel}: {type(exc).__name__}: {exc}"
            if unresolved:
                detail += f" (unresolved global: {', '.join(unresolved)})"
            result["errors"].append(detail)
            result["weights_unreadable"].append({"file": rel, "why": type(exc).__name__,
                                                 "unresolved": unresolved})
            _record("weights.unreadable", detail)

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
    if mode == "baseline":
        return mode_baseline(sys.argv[2])
    print(f"unknown mode {mode!r}")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
