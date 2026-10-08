#!/usr/bin/env python3
"""Fetch real, published **Nepali-language** model artifacts.

The challenge is explicitly about the Nepali open-source community, and a generic tool
with no local evidence would be a weaker entry than the same tool pointed at the models
Nepali builders actually download. These are real repositories by Nepali authors and
Nepali research groups, fetched as a third-party control set just like `corpus-real/`.

Sizes are why this is a separate script: the Nepali ecosystem distributes overwhelmingly
as GGUF quantisations, and a naive fetch of one quantisation repository is 5.7 GB. Each
entry names the exact files it wants and the total is printed.

    python scripts/fetch_nepali_models.py

Writes to corpus-nepali/<name>/. Requires network the first time.
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DEST_ROOT = ROOT / "corpus-nepali"

# (repo_id, local name, allow_patterns, why it is in the set)
REPOS = [
    ("jangedoo/all-MiniLM-L6-v2-nepali", "nepali-minilm-embedder",
     ["*.json", "*.md", "*.txt", "*.safetensors"],
     "a Nepali sentence-embedding model in safetensors form"),
    ("Rajan/NepaliBERT", "nepali-bert",
     ["*.json", "*.md", "*.txt", "*.bin"],
     "one of the most-downloaded Nepali BERT models, shipped as a .bin checkpoint"),
    ("mradermacher/Qwen-0.6b-nepali-instruct-GGUF", "nepali-qwen-gguf",
     ["Qwen-0.6b-nepali-instruct.Q2_K.gguf", "*.json", "*.md", "*.txt"],
     "a Nepali-tuned Qwen quantised to GGUF — the format this community actually ships. "
     "Only the smallest quantisation is fetched, deliberately"),
    # --- the case that matters most: repositories that FORCE trust_remote_code=True.
    # Found by scripts/find_remote_code_models.py: 46 of 268 Nepali/Indic repositories ship
    # .py files and 15 declare auto_map. Neither picklescan nor fickling opens a .py file.
    ("ujjwal5454/nepali-voice-engine-v4", "nepali-voice-engine",
     ["*.py", "config.json", "tokenizer.json", "*.txt"],
     "a NEPALI model with a custom architecture (NepaliVoiceEngine): auto_map points AutoModel at "
     "modeling_nepali_voice.py, so using it means running the author's Python on your machine. "
     "The 3.7 GB weights and the dataset zips are excluded — the question here is the code path"),
    ("prajdabre/rotary-indictrans2-en-indic-dist-200M", "indic-trans2-rotary",
     ["*.py", "*.json", "*.md", "*.bin", "*.SRC", "*.TGT", "*.model", "*.txt"],
     "an Indic translation model (IndicTrans2 covers Nepali) with a custom architecture AND a real "
     "847 MB pickle checkpoint, so it exercises both the code path and the deserialisation path"),
]


def main() -> int:
    try:
        from huggingface_hub import snapshot_download
    except ImportError:
        print("install first:  uv pip install --python .venv/bin/python huggingface_hub")
        return 2

    DEST_ROOT.mkdir(exist_ok=True)
    total_bytes = 0
    for repo_id, name, patterns, why in REPOS:
        dest = DEST_ROOT / name
        dest.mkdir(exist_ok=True)
        try:
            snapshot_download(repo_id=repo_id, local_dir=str(dest), allow_patterns=patterns)
        except Exception as exc:                      # noqa: BLE001 - report, do not crash
            print(f"FAIL {repo_id}: {type(exc).__name__}: {str(exc)[:140]}")
            continue
        files = sorted(f for f in dest.rglob("*") if f.is_file())
        size = sum(f.stat().st_size for f in files)
        total_bytes += size
        print(f"OK   {name:24} {len(files):2} files {size/1e6:8.2f} MB   ({repo_id})")
        print(f"       why: {why}")
        for f in files:
            print(f"       {f.relative_to(dest)}  {f.stat().st_size/1e6:.2f} MB")
    print(f"\ntotal {total_bytes/1e6:.1f} MB")
    return 0


if __name__ == "__main__":
    sys.exit(main())
