#!/usr/bin/env bash
# Render every slide of the Demo Day deck and prove none of them is blank.
#
# This exists because the deck once read `location.hash` only on load, so deep links silently
# showed the wrong slide - a bug that only a render finds. Reading the HTML cannot tell you
# whether a slide draws.
#
# It is deliberately NOT part of the eligibility gate or CI: it needs chromium, and a gate that
# breaks the build when an optional binary is absent is worse than the check it adds. That
# mistake was made once with ffprobe; the gate reads the mp4 duration from the file instead.
# Run this before a demo, not on every push.
#
#   ./scripts/check_deck_renders.sh

set -uo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DECK="$ROOT/presentation/quarantine-demo-day.html"
OUT="${TMPDIR:-/tmp}/deck-render"
SLIDES="$(grep -c 'class="slide' "$DECK")"

for exe in chromium magick; do
  command -v "$exe" >/dev/null 2>&1 || { echo "missing $exe - this check is local-only, by design"; exit 2; }
done

rm -rf "$OUT"; mkdir -p "$OUT"
echo "rendering $SLIDES slides from $(basename "$DECK") ..."

blank=0
for n in $(seq 1 "$SLIDES"); do
  png="$OUT/s$(printf '%02d' "$n").png"
  timeout 60 chromium --headless=new --no-sandbox --disable-gpu --hide-scrollbars \
    --window-size=1440,900 --screenshot="$png" "file://$DECK#s$n" >/dev/null 2>&1
  if [ ! -s "$png" ]; then
    printf '  %sFAIL%s slide %-3s did not render\n' "$(printf '\033[31m')" "$(printf '\033[0m')" "$n"
    blank=$((blank + 1)); continue
  fi
  # A rendered slide has contrast; a blank one is a flat rectangle.
  spread="$(magick identify -format '%[fx:standard_deviation]' "$png" 2>/dev/null || echo 0)"
  if awk "BEGIN{exit !($spread < 0.02)}"; then
    printf '  %sFAIL%s slide %-3s is blank (sd=%s)\n' "$(printf '\033[31m')" "$(printf '\033[0m')" "$n" "$spread"
    blank=$((blank + 1))
  else
    printf '  ok   slide %-3s (sd=%s)\n' "$n" "$spread"
  fi
done

if [ "$blank" -gt 0 ]; then
  echo
  echo "$blank of $SLIDES slides did not render. The deck is a hash-navigated page: check that it"
  echo "reads location.hash on load AND listens for hashchange."
  exit 1
fi

sheet="$OUT/contact-sheet.png"
magick montage "$OUT"/s*.png -tile 4x4 -geometry 420x263+6+6 -background '#0b0f14' "$sheet" 2>/dev/null
echo
echo "all $SLIDES slides render."
[ -s "$sheet" ] && echo "contact sheet for a human to check: $sheet"
echo "Open the deck in a browser before the demo - this proves it draws, not that it reads well."
exit 0
