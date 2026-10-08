#!/usr/bin/env bash
# One command that tells you what is missing, in plain language, and then runs the product.
#
# The failure mode this exists for: someone clones the repo, runs the documented command, and gets
# a traceback about a container runtime or a port. That reads as "this does not work" when the
# truth is "one prerequisite is absent". So check first, say what is missing and how to fix it,
# and only then run anything.
#
#   ./scripts/try_it.sh                        # one artifact, the whole agent team
#   ./scripts/try_it.sh corpus/probe-file-read # or any artifact directory of your own

set -uo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
ARTIFACT="${1:-corpus/probe-custom-generate}"
MODEL_URL="${QUARANTINE_MODEL_URL:-http://127.0.0.1:8081/v1/chat/completions}"

bold=$'\033[1m'; dim=$'\033[2m'; red=$'\033[31m'; green=$'\033[32m'; yellow=$'\033[33m'; off=$'\033[0m'
missing=()

say()  { printf '%s\n' "$*"; }
ok()   { printf '  %s✓%s %s\n' "$green" "$off" "$*"; }
warn() { printf '  %s!%s %s\n' "$yellow" "$off" "$*"; }
bad()  { printf '  %s✗%s %s\n' "$red" "$off" "$*"; }

say "${bold}Quarantine — checking what this machine already has${off}"
say ""

# --- python / the package ---------------------------------------------------
if [ -x "$ROOT/.venv/bin/python" ]; then
  ok "virtualenv at .venv"
else
  bad "no .venv — create it with:  uv venv --python 3.12 .venv && uv pip install --python .venv/bin/python -e \".[dev]\""
  missing+=("venv")
fi
PY="$ROOT/.venv/bin/python"
if [ -x "$PY" ] && "$PY" -c "import quarantine" 2>/dev/null; then
  ok "the quarantine package is importable"
else
  [ -x "$PY" ] && bad "the package is not installed — uv pip install --python .venv/bin/python -e \".[dev]\"" && missing+=("package")
fi

# --- container runtime ------------------------------------------------------
if command -v docker >/dev/null 2>&1; then
  if docker info >/dev/null 2>&1; then
    ok "docker is running"
  else
    bad "docker is installed but not running — start Docker Desktop, or: sudo systemctl start docker"
    missing+=("docker-daemon")
  fi
else
  bad "docker is not installed — the artifact must run contained; https://docs.docker.com/get-docker/"
  missing+=("docker")
fi

# --- the local model --------------------------------------------------------
if curl -s -o /dev/null --max-time 3 "$MODEL_URL" 2>/dev/null || \
   curl -s -o /dev/null --max-time 3 "${MODEL_URL%/chat/completions}" 2>/dev/null; then
  ok "a local model is answering on ${MODEL_URL%/*}"
else
  bad "no model at ${MODEL_URL%/*} — start the local open-weight model with:  ./scripts/serve_model.sh &"
  warn "no API key is needed, and none is used: the model runs on this machine"
  missing+=("model")
fi

# --- the artifact -----------------------------------------------------------
if [ -d "$ROOT/$ARTIFACT" ]; then
  ok "artifact: $ARTIFACT"
else
  bad "no such artifact: $ARTIFACT"
  warn "try one of: $(cd "$ROOT" && ls -d corpus/probe-* 2>/dev/null | head -3 | tr '\n' ' ')"
  missing+=("artifact")
fi

say ""
if [ ${#missing[@]} -gt 0 ]; then
  say "${bold}${#missing[@]} thing(s) to fix first.${off} Nothing was run, so nothing looked broken."
  exit 2
fi

say "${bold}All set. Running one artifact through the whole agent team.${off}"
say "${dim}exit 0 = allow · 1 = block · 2 = unknown (referred to a human)${off}"
say ""
OUT="$ROOT/runs/try-it"
rm -rf "$OUT"
"$ROOT/.venv/bin/quarantine" inspect "$ARTIFACT" --out "$OUT"
code=$?

say ""
if [ -f "$OUT/receipt.json" ]; then
  say "${bold}And the receipt, checked by a program that is not ours:${off}"
  "$PY" "$ROOT/tools/verify_receipt_standalone.py" "$OUT/receipt.json" \
        --pub "$OUT/keys/quarantine.pub.pem" || true
  say ""
  say "${dim}receipt: $OUT/receipt.json${off}"
fi
say ""
case "$code" in
  0) say "${green}ALLOW${off} — observed, and nothing capability-like happened." ;;
  1) say "${red}BLOCK${off} — it did something its declaration does not permit." ;;
  2) say "${yellow}UNKNOWN${off} — we could not look. A human decides; this is not a pass." ;;
esac
exit 0
