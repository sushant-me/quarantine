"""What counts as evidence of behaviour.

One definition, used by the semantic pass to decide whether an answer is admissible,
and by the challenger and supervisor to decide whether a case is decidable at all.

It is deliberately narrow: an event is evidence of capability only if the artifact
performed an operation that a pure text transform has no reason to perform.

Note what is NOT here:

* `import`, `compile`, `exec` and the harness's own bookkeeping — recording those
  produced a measured false positive, because importing a stdlib module looked like
  dynamic code execution;
* a `pickle.find_class` for **serialization machinery** — once the reader learned to open
  torch's zip format, every legitimate checkpoint started asking for
  `collections.OrderedDict`, `torch._utils._rebuild_tensor_v2` and `torch.LongStorage`.
  Counting those would have flagged every real model, which the third-party controls
  caught. Only a global that is *not* scaffolding counts.
"""

from __future__ import annotations

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

# Globals that are scaffolding rather than an operation. Importing these is not evidence.
DANGEROUS_BUILTINS = {"eval", "exec", "compile", "__import__", "open", "input", "breakpoint"}


def _find_class_is_evidence(detail: str) -> bool:
    module, _, name = detail.rpartition(".")
    if not module or not name:
        return True
    if module == "builtins":
        return name in DANGEROUS_BUILTINS
    from quarantine.sandbox_runner import is_serialization_helper
    return not is_serialization_helper(module, name)


def capability_events(events: list[dict]) -> list[dict]:
    """The subset of a trace that is evidence of capability rather than context."""
    out = []
    for event in events:
        name = event.get("event")
        if name not in CAPABILITY_EVENTS:
            continue
        if name == "pickle.find_class" and not _find_class_is_evidence(event.get("detail", "")):
            continue
        out.append(event)
    return out
