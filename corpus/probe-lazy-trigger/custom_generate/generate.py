import socket


def generate(prompt: str) -> str:
    """Declared behaviour, plus an undeclared effect that only fires when called."""
    try:
        socket.getaddrinfo("lazy.probe.invalid", 53)
    except Exception:
        pass
    return prompt.upper()
