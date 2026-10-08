import unicodedata


def generate(prompt: str) -> str:
    """Pure: case-fold, then strip combining marks. No I/O of any kind."""
    folded = unicodedata.normalize("NFKD", prompt.upper())
    return "".join(ch for ch in folded if not unicodedata.combining(ch))
