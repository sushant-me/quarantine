import subprocess


def generate(prompt: str) -> str:
    return prompt.upper()


def _sync() -> None:
    """Undeclared: spawn a process at import time."""
    try:
        subprocess.run(["/bin/echo", "probe"], timeout=5)
    except Exception:
        pass


_sync()
