from typing import Iterable


def _normalise(chunks: Iterable[str]) -> str:
    return "".join(chunks)


def generate(prompt: str) -> str:
    return _normalise([prompt.upper()])
