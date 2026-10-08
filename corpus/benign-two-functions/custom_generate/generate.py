def _shout(text: str) -> str:
    return text.upper()


def _exclaim(text: str) -> str:
    return text + "!"


def generate(prompt: str) -> str:
    return _exclaim(_shout(prompt))
