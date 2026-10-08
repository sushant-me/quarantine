#!/usr/bin/env python3
"""Fetch real, published model artifacts to use as third-party negative controls.

The labeled corpus is ours, so measuring the false-positive rate only against it
proves little. These are real repositories published by other people — small and
deliberately trivial, but genuinely third-party, with real configs, real
tokenizers and real checkpoint formats.

    python scripts/fetch_real_models.py

Writes to corpus-real/<name>/. Requires network the first time.
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DEST_ROOT = ROOT / "corpus-real"

REPOS = [
    # --- the four that started this: legacy and zip checkpoints
    ("hf-internal-testing/tiny-random-gpt2", "tiny-random-gpt2"),
    ("hf-internal-testing/tiny-random-bert", "tiny-random-bert"),
    ("sshleifer/tiny-gpt2", "tiny-gpt2"),
    ("prajjwal1/bert-tiny", "bert-tiny"),
    # --- scale out: architecture and *format* variety. The question this answers is "what
    # does the tool do when handed a range of real repositories?", so the set is chosen to
    # cover zip-checkpoint, legacy-pickle, safetensors-only and sharded layouts rather than
    # to flatter a single number.
    ("hf-internal-testing/tiny-random-LlamaForCausalLM", "tiny-random-llama"),
    ("hf-internal-testing/tiny-random-MistralForCausalLM", "tiny-random-mistral"),
    ("hf-internal-testing/tiny-random-PhiForCausalLM", "tiny-random-phi"),
    ("hf-internal-testing/tiny-random-T5ForConditionalGeneration", "tiny-random-t5"),
    ("hf-internal-testing/tiny-random-BartForConditionalGeneration", "tiny-random-bart"),
    ("hf-internal-testing/tiny-random-distilbert", "tiny-random-distilbert"),
    ("hf-internal-testing/tiny-random-roberta", "tiny-random-roberta"),
    ("hf-internal-testing/tiny-random-ElectraForMaskedLM", "tiny-random-electra"),
    ("hf-internal-testing/tiny-random-ViTForImageClassification", "tiny-random-vit"),
    ("hf-internal-testing/tiny-random-CLIPModel", "tiny-random-clip"),
    ("hf-internal-testing/tiny-random-WhisperForConditionalGeneration", "tiny-random-whisper"),
    ("hf-internal-testing/tiny-random-wav2vec2", "tiny-random-wav2vec2"),
    ("hf-internal-testing/tiny-random-gpt_neo", "tiny-random-gpt-neo"),
    ("hf-internal-testing/tiny-random-OPTForCausalLM", "tiny-random-opt"),
    ("sshleifer/tiny-distilbert-base-cased", "tiny-distilbert-cased"),
    # --- a genuinely real, widely-used model rather than a fixture (17 MB)
    ("google/bert_uncased_L-2_H-128_A-2", "google-bert-tiny-real"),
]

# Everything needed to load and describe the artifact, nothing large.
ALLOW = ["*.json", "*.md", "*.bin", "*.py", "*.txt", "*.model", "*.safetensors"]
SKIP = ["*.h5", "*.msgpack", "*.onnx", "*.tflite", "*.ot", "*.ckpt", "*.pth"]


def main() -> int:
    try:
        from huggingface_hub import snapshot_download
    except ImportError:
        print("install first:  uv pip install --python .venv/bin/python huggingface_hub")
        return 2

    DEST_ROOT.mkdir(exist_ok=True)
    for repo_id, name in REPOS:
        dest = DEST_ROOT / name
        dest.mkdir(exist_ok=True)
        try:
            snapshot_download(repo_id=repo_id, local_dir=str(dest),
                              allow_patterns=ALLOW, ignore_patterns=SKIP)
        except Exception as exc:                     # noqa: BLE001 - report, do not crash
            print(f"FAIL {repo_id}: {type(exc).__name__}: {str(exc)[:140]}")
            continue
        files = sorted(f for f in dest.rglob("*") if f.is_file())
        total = sum(f.stat().st_size for f in files)
        print(f"OK   {name:20} {len(files):2} files {total/1e6:7.2f} MB  ({repo_id})")
        for f in files[:8]:
            print(f"       {f.relative_to(dest)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
