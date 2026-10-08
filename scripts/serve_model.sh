#!/usr/bin/env bash
# Start the local open-weight model server. No API key, no network, no vendor.
# Measured rule from the earlier stack work: never use all threads (SMT collapse).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
AISTACK="${AISTACK:-/home/logic/win/aistack}"
# The default is the model every document, receipt and measurement in this repository refers
# to. It used to default to the 1.5B instruct model, so the documented quickstart served a
# different model than the documentation described. Lower-RAM alternative:
#   MODEL=$AISTACK/gguf/qwen2.5-1.5b-instruct-q4_k_m.gguf ./scripts/serve_model.sh
MODEL="${MODEL:-$AISTACK/gguf/qwen2.5-coder-3b-instruct-q4_k_m.gguf}"
PORT="${PORT:-8081}"
THREADS="${THREADS:-6}"
NGL="${NGL:-99}"

BIN="$AISTACK/llama.cpp/build/bin/llama-server"
if [ ! -x "$BIN" ]; then echo "missing $BIN" >&2; exit 3; fi
if [ ! -f "$MODEL" ]; then echo "missing model $MODEL" >&2; exit 3; fi

export LD_LIBRARY_PATH="$AISTACK/llama.cpp/build/bin:${LD_LIBRARY_PATH:-}"
echo "serving $(basename "$MODEL") on 127.0.0.1:$PORT (threads=$THREADS, ngl=$NGL)"
exec "$BIN" -m "$MODEL" --host 127.0.0.1 --port "$PORT" -t "$THREADS" -ngl "$NGL" -c 4096
