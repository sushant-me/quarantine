"""What counts as evidence of behaviour.

One definition, used by the semantic pass to decide whether an answer is admissible.
It is deliberately narrow: an event is evidence of capability only if the artifact
performed an operation that a pure text transform has no reason to perform.

Note what is NOT here: `import`, `compile`, `exec` and the harness's own bookkeeping.
Recording those produced a measured false positive — the benign control was blocked
because importing a stdlib module looked like dynamic code execution.
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
    # deserialization intent
    "pickle.find_class",
    # native
    "ctypes.dlopen", "ctypes.dlsym", "ctypes.call_function",
    # mutation of the host
    "shutil.copyfile", "shutil.move", "os.remove", "os.rename", "os.mkdir", "os.rmdir",
    "os.putenv", "os.unsetenv",
}


def capability_events(events: list[dict]) -> list[dict]:
    """The subset of a trace that is evidence of capability rather than context."""
    return [e for e in events if e.get("event") in CAPABILITY_EVENTS]
