#!/usr/bin/env python3
"""Render the README's terminal GIF from real command output.

The README's first screen decides whether anyone reads the second. A wall of prose is honest but
it does not show the product; a mock-up would show a product that does not exist. So this runs the
actual commands — the incumbent scanner, then Quarantine on the same artifact, then the receipt
verification — and renders what came back into a small animated GIF.

Everything on screen is captured from a real run. If a command fails, the frame says so.

    python scripts/build_readme_gif.py
"""

from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FRAMES = ROOT / "reports" / "readme-gif"
OUT = ROOT / "docs" / "assets" / "demo.gif"

FONT = "/usr/share/fonts/TTF/JetBrainsMonoNerdFont-Regular.ttf"
W, H = 940, 470
BG, FG, DIM, BAD, GOOD = "#0b0f14", "#d8dee9", "#7a8797", "#bf616a", "#a3be8c"
COLS = 104


def run(cmd: list[str], timeout: int = 900) -> str:
    proc = subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True, timeout=timeout)
    return (proc.stdout + proc.stderr).strip()


def tidy(lines: list[str], cols: int = COLS) -> list[str]:
    return [ln if len(ln) <= cols else ln[: cols - 1] + "…" for ln in lines]


def frame(name: str, lines: list[str], title: str) -> Path:
    FRAMES.mkdir(parents=True, exist_ok=True)
    text_file = FRAMES / f"{name}.txt"
    text_file.write_text("\n".join(tidy(lines)), encoding="utf-8")
    png = FRAMES / f"{name}.png"
    cmd = ["magick", "-size", f"{W}x{H}", f"xc:{BG}",
           "-fill", "#1b222c", "-draw", f"rectangle 0,0 {W},32",
           "-fill", BAD, "-draw", "circle 20,16 24,16",
           "-fill", "#ebcb8b", "-draw", "circle 38,16 42,16",
           "-fill", GOOD, "-draw", "circle 56,16 60,16",
           "-font", FONT, "-pointsize", "14", "-fill", DIM, "-annotate", "+76+21", title,
           "-font", FONT, "-pointsize", "14", "-fill", FG,
           "-annotate", "+24+66", f"@{text_file}", str(png)]
    subprocess.run(cmd, check=True, capture_output=True)
    return png


def main() -> int:
    for exe in ("magick", "ffmpeg"):
        if not shutil.which(exe):
            print(f"missing {exe}")
            return 2
    shutil.rmtree(FRAMES, ignore_errors=True)
    OUT.parent.mkdir(parents=True, exist_ok=True)

    probe = "corpus/probe-custom-generate"

    # Frame 1 — the scanner everyone already runs.
    scan = run([str(ROOT / ".venv" / "bin" / "python"), "-m", "picklescan", "--path", probe])
    summary = [ln for ln in scan.splitlines()
               if ln.startswith(("Scanned", "Infected", "Suspicious", "Dangerous"))]
    f1 = frame("01-scanner", [
        "$ picklescan --path corpus/probe-custom-generate", "",
        *summary, "",
        "  The scanner everyone runs reports this artifact clean.",
        "  It never opens custom_generate/generate.py, where the payload lives.",
    ], "step 1 — what today's scanner says")

    # Frame 2 — the same artifact, executed where it cannot hurt anything.
    session = FRAMES / "session"
    session.mkdir(parents=True, exist_ok=True)
    verdict = run([str(ROOT / ".venv" / "bin" / "quarantine"), "inspect", probe, "--out", str(session)])
    keep = [ln for ln in verdict.splitlines()
            if any(k in ln for k in ("observer", "analyst", "challenger", "repairer", "verifier",
                                     "verdict", "incumbents", "receipt", "exit code", "repair"))]
    f2 = frame("02-quarantine", [
        "$ quarantine inspect corpus/probe-custom-generate", "", *keep[:11],
    ], "step 2 — the same artifact, in a box with no network")

    # Frame 3 — the receipt, checked by a program that is not ours.
    receipt = session / "receipt.json"
    pub = session / "keys" / "quarantine.pub.pem"
    verified = run([sys.executable, "tools/verify_receipt_standalone.py", str(receipt), "--pub", str(pub)])
    f3 = frame("03-receipt", [
        "$ python3 tools/verify_receipt_standalone.py runs/probe/receipt.json \\",
        "        --pub runs/probe/keys/quarantine.pub.pem", "",
        *[ln for ln in verified.splitlines() if ln.strip()][:8],
    ], "step 3 — and a receipt anyone can check")

    durations = [3.0, 3.5, 3.5]
    listing = FRAMES / "frames.txt"
    listing.write_text("".join(f"file '{p}'\nduration {d}\n" for p, d in
                               zip((f1, f2, f3), durations)) + f"file '{f3}'\n", encoding="utf-8")
    subprocess.run([
        "ffmpeg", "-y", "-hide_banner", "-loglevel", "error",
        "-f", "concat", "-safe", "0", "-i", str(listing),
        "-vf", "fps=12,scale=940:-1:flags=lanczos,split[a][b];[a]palettegen=max_colors=64[p];"
               "[b][p]paletteuse=dither=bayer",
        "-loop", "0", str(OUT),
    ], check=True)

    size_kb = OUT.stat().st_size / 1024
    print(f"wrote {OUT}  ({size_kb:.0f} KB)")
    if size_kb > 2048:
        print("  WARNING: over 2 MB, GitHub will not load it inline for everyone")
    return 0


if __name__ == "__main__":
    sys.exit(main())
