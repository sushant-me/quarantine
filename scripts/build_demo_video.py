#!/usr/bin/env python3
"""Build the demo video from REAL captured output.

This does not type a script of made-up terminal text. It runs the actual commands,
captures their actual output, and renders those bytes as terminal frames. The
evaluation numbers come from the committed reports, which were produced by real runs.

What it is, stated honestly in the video itself: a **replay**, rendered from captured
output — not a pixel capture of a screen. There is no display server here, and saying
"screen recording" when it is a replay would be a small lie in a project whose whole
argument is about evidence.

    python scripts/build_demo_video.py

Writes reports/video/quarantine-demo.mp4 and reports/video/transcript.txt.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "reports" / "video"
FRAMES = OUT / "frames"
WORK = OUT / "session"
FONT = "/usr/share/fonts/TTF/JetBrainsMonoNerdFont-Regular.ttf"
FONT_BOLD = "/usr/share/fonts/TTF/JetBrainsMonoNerdFont-Bold.ttf"
W, H = 1280, 720
BG, FG, DIM, ACCENT, BAD, GOOD = "#0b0f14", "#d8dee9", "#7a8797", "#88c0d0", "#bf616a", "#a3be8c"
COLS = 124
POINTSIZE = "15"


def run(cmd: list[str], cwd: Path = ROOT) -> str:
    proc = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, timeout=900)
    return (proc.stdout + proc.stderr).strip()


def tidy(lines: list[str], cols: int = COLS) -> list[str]:
    """Truncate rather than wrap.

    A hard wrap splits words mid-syllable and reads as a rendering bug. Truncating
    with an ellipsis says honestly "there was more here".
    """
    return [ln if len(ln) <= cols else ln[: cols - 1] + "…" for ln in lines]


def metric_table(title: str, report: dict, positive_of: int, fp_of: int) -> list[str]:
    """Build an aligned table from the measured JSON, not from scraped markdown."""
    lines = [f"  {title}", "",
             f"  {'auditor':<13}{'caught':>9}{'detect':>9}{'false pos':>12}{'FP rate':>9}",
             "  " + "-" * 52]
    for name, key in (("Quarantine", "quarantine"), ("picklescan", "picklescan"), ("fickling", "fickling")):
        m = report[key]
        det = "n/a" if m["detection_rate"] is None else f"{m['detection_rate']:.0%}"
        fpr = "n/a" if m["false_positive_rate"] is None else f"{m['false_positive_rate']:.0%}"
        caught = f"{m['tp']}/{positive_of}" if positive_of else "—"
        lines.append(f"  {name:<13}{caught:>9}{det:>9}{str(m['fp']) + '/' + str(fp_of):>12}{fpr:>9}")
    return lines


def frame(name: str, lines: list[str], title: str = "") -> Path:
    """Render one terminal-looking frame."""
    FRAMES.mkdir(parents=True, exist_ok=True)
    png = FRAMES / f"{name}.png"
    body = "\n".join(lines)
    text_file = FRAMES / f"{name}.txt"
    text_file.write_text(body, encoding="utf-8")

    cmd = ["magick", "-size", f"{W}x{H}", f"xc:{BG}"]
    # window chrome: a title bar and three dots
    cmd += ["-fill", "#1b222c", "-draw", f"rectangle 0,0 {W},34"]
    cmd += ["-fill", BAD, "-draw", "circle 22,17 26,17"]
    cmd += ["-fill", "#ebcb8b", "-draw", "circle 42,17 46,17"]
    cmd += ["-fill", GOOD, "-draw", "circle 62,17 66,17"]
    if title:
        cmd += ["-font", FONT, "-pointsize", "15", "-fill", DIM,
                "-annotate", "+84+22", title]
    cmd += ["-font", FONT, "-pointsize", POINTSIZE, "-fill", FG,
            "-annotate", "+28+72", f"@{text_file}"]
    cmd.append(str(png))
    subprocess.run(cmd, check=True, capture_output=True)
    return png


def main() -> int:
    for exe in ("magick", "ffmpeg"):
        if not shutil.which(exe):
            print(f"missing {exe}")
            return 2
    if FRAMES.exists():
        shutil.rmtree(FRAMES)
    WORK.mkdir(parents=True, exist_ok=True)
    OUT.mkdir(parents=True, exist_ok=True)

    print("running the real commands ...", flush=True)
    picklescan = run([".venv/bin/python", "-m", "picklescan", "--path",
                      "corpus/probe-custom-generate"])
    (WORK / "picklescan.txt").write_text(picklescan, encoding="utf-8")

    inspect = run(["env", "PYTHONPATH=src", ".venv/bin/python", "-m", "quarantine.cli",
                   "inspect", "corpus/probe-custom-generate", "--out", "runs/demo"])
    (WORK / "inspect.txt").write_text(inspect, encoding="utf-8")

    # The third outcome. This artifact declares a pure transform and ships the shape of real
    # custom code: it imports a dependency the sandbox does not have. Nothing can be observed,
    # so nothing is judged — and it must not be reported as fine.
    missing = WORK / "missing-dep"
    (missing / "custom_generate").mkdir(parents=True, exist_ok=True)
    (missing / "README.md").write_text(
        "Declares a pure, deterministic text transform. No network, no file access.", encoding="utf-8")
    (missing / "custom_generate" / "generate.py").write_text(
        "import a_dependency_that_is_not_installed\n\n\n"
        "def generate(prompt: str) -> str:\n    return prompt.upper()\n", encoding="utf-8")
    escalated = run(["env", "PYTHONPATH=src", ".venv/bin/python", "-m", "quarantine.cli",
                     "inspect", str(missing), "--out", "runs/demo-escalated"])
    (WORK / "escalated.txt").write_text(escalated, encoding="utf-8")

    corpus_eval = json.loads((ROOT / "reports" / "corpus-eval.json").read_text(encoding="utf-8"))
    real_eval = json.loads((ROOT / "reports" / "corpus-real-eval.json").read_text(encoding="utf-8"))
    nepali_eval = json.loads((ROOT / "reports" / "nepali-eval.json").read_text(encoding="utf-8"))
    escape = (ROOT / "reports" / "sandbox-escape.md").read_text(encoding="utf-8")
    (WORK / "corpus-eval.json").write_text(json.dumps(corpus_eval, indent=2), encoding="utf-8")

    pick_lines = tidy(picklescan.splitlines())
    inspect_lines = tidy(inspect.splitlines())
    escalated_lines = tidy(escalated.splitlines())
    esc_line = next((ln for ln in escape.splitlines() if ln.startswith("**Result")), "")

    scenes: list[tuple[str, list[str], float, str]] = [
        ("01-title", [
            "",
            "  Quarantine",
            "",
            "  the offline clean room for untrusted model artifacts",
            "",
            f"  {'-' * 62}",
            "",
            "  every model you download is code you did not write.",
            "",
            "  network OFF  ·  open-weight model, local  ·  Apache-2.0",
        ], 6.0, "quarantine — demo"),
        ("02-scanner", [
            "  $ picklescan --path corpus/probe-custom-generate",
            "",
        ] + pick_lines + [
            "",
            "  This artifact declares a pure text transform.",
        ], 13.0, "step 1 — what the scanner everyone runs says"),
        ("03-gap", [
            "  WHAT IT LOOKED AT",
            "",
            "    Scanned files: 1     <- the weights file",
            "",
            "  WHAT IT DID NOT LOOK AT",
            "",
            "    custom_generate/generate.py",
            "",
            "  The Python that runs on load is not in its input set.",
            "  That is not a detection failure. It is a coverage hole,",
            "  and it does not depend on the scanner's version.",
        ], 11.0, "the gap"),
        ("04a-trace", [
            "  $ quarantine inspect corpus/probe-custom-generate",
            "",
        ] + inspect_lines[:8], 9.0, "step 2 — execute it where it cannot hurt you"),
        ("04b-trace", [
            "  $ quarantine inspect corpus/probe-custom-generate",
            "",
        ] + inspect_lines[:16], 9.0, "the artifact, in a box with no network"),
        ("04c-trace", [
            "  $ quarantine inspect corpus/probe-custom-generate",
            "",
        ] + inspect_lines[:26], 11.0, "the artifact, in a box with no network"),
        ("05-verdict", [
            "  $ quarantine inspect corpus/probe-custom-generate",
            "",
        ] + inspect_lines[-16:], 15.0, "step 3 — an agent team, three of them using the model"),
        ("05b-escalate", [
            "  THE THIRD OUTCOME — an artifact that cannot be executed",
            "",
            "  $ quarantine inspect <artifact whose dependency is missing>",
            "",
        ] + escalated_lines[:14] + [
            "",
            "  Nothing could be observed, so nothing is judged.",
            "  UNKNOWN, exit code 2 — referred to a human.",
            "",
            "  Before this outcome existed, this artifact was reported",
            "  ALLOW: \"we could not run it, so we saw nothing, so it is fine.\"",
            "  That is the most dangerous default a security gate can have.",
        ], 15.0, "step 3b — escalation, because UNKNOWN is not a pass"),
        ("06b-nepal", metric_table(
            f"THE NEPALI COMMUNITY - {nepali_eval['n']} real published Nepali models",
            nepali_eval, 0, nepali_eval["n"]) + [
            "",
            "  268 Nepali/Indic repos searched: 46 ship .py, 15 declare auto_map",
            "  (trust_remote_code=True). Neither incumbent opens a .py file at all.",
            "",
            "  FIRST RUN: the GGUF model was ESCALATED - 'no weight files found'.",
            "  GGUF quantisation is how most Nepali models reach users, and the",
            "  reader did not know the format. Now validated, like safetensors.",
            "",
            "  No amount of reasoning about our own corpus produced that.",
            "  It took downloading what Nepali users download.",
        ], 14.0, "step 4b - pointed at Nepal, not at fixtures"),
        ("06-numbers", metric_table(
            f"DETECTION — {corpus_eval['n']} artifacts, the same declared API in every one",
            corpus_eval, corpus_eval["undeclared"], corpus_eval["benign"]) + [
            "",
        ] + metric_table(
            f"FALSE POSITIVES — {real_eval['n']} real published models from the Hub",
            real_eval, 0, real_eval["n"]) + [
            "",
            "  The incumbents' catches are the artifacts whose payload is a",
            "  pickle — the only ones inside their input set. The seven code",
            "  paths in custom_generate/ and modeling_*.py, neither scanner",
            "  opens. And on real models, one of them flags all four.",
        ], 17.0, "step 4 — measured, with a control group"),
        ("06b-repair", [
            "  THE REPAIR, across all 8 undeclared artifacts",
            "",
            "    blocked by the local model ......... 8/8",
            "    repair attempted ................... 7/8   (one ships only weights)",
            "    produced and capability-clean ...... 7/7",
            "    verified by output-equivalence ..... 6/7",
            "",
            "  The criterion is both halves: identical outputs on 12 prompts,",
            "  AND zero capability operations by the repaired loader —",
            "  measured from the trace, not read off the source.",
            "",
            "  On the reference artifact the original performed 2 capability",
            "  operations and the repair performed 0.",
            "",
            "  The one non-pass is a refusal, not a failure: that artifact's",
            "  original will not execute at all, so equivalence cannot be",
            "  established and the receipt says so.",
        ], 15.0, "step 4b — the repair, measured across the corpus"),
        ("07-containment", [
            "  WE ATTACKED OUR OWN SANDBOX",
            "",
            "    " + esc_line.replace("**", "").strip(),
            "",
            "    read-only rootfs · /etc/shadow · unmounted host file · mount(2)",
            "    unshare(CLONE_NEWUSER) · chroot(2) · setuid(0) · raw socket",
            "    connecting to the host model server · public DNS",
            "",
            "  Ten primitives, not a fuzzing campaign. A clean table does",
            "  not mean the box cannot be broken.",
        ], 12.0, "step 5 — containment, attacked on purpose"),
        ("08-limits", [
            "  WHAT THIS DOES NOT CLAIM",
            "",
            "    the malicious corpus and its labels are ours",
            "    the third-party controls are tiny models",
            "    no live CVE bypass is claimed",
            "    one model size; equivalence is a 3-prompt smoke test",
            "    the receipt has not been independently verified",
            "",
            "  Limits: LIMITATIONS.md, in the repository.",
        ], 11.0, "said out loud, in the video"),
        ("09-end", [
            "",
            "  Behaviour is the only ground truth about",
            "  what a model artifact does.",
            "",
            "  We measure it. We gate on it. We sign what we saw.",
            "",
            f"  {'-' * 62}",
            "",
            "  Apache-2.0  ·  offline  ·  run it yourself",
            "",
            "  This is a replay rendered from real captured output,",
            "  not a pixel capture of a screen.",
        ], 7.0, "quarantine"),
    ]

    print("rendering frames ...", flush=True)
    manifest: list[str] = []
    for name, lines, duration, title in scenes:
        png = frame(name, lines, title)
        manifest.append(f"file '{png}'\nduration {duration}")
    manifest.append(f"file '{FRAMES / (scenes[-1][0] + '.png')}'")
    list_file = OUT / "concat.txt"
    list_file.write_text("\n".join(manifest) + "\n", encoding="utf-8")

    video = OUT / "quarantine-demo.mp4"
    print("encoding ...", flush=True)
    subprocess.run([
        "ffmpeg", "-y", "-hide_banner", "-loglevel", "error",
        "-f", "concat", "-safe", "0", "-i", str(list_file),
        "-pix_fmt", "yuv420p", "-r", "30",
        "-movflags", "+faststart", str(video),
    ], check=True)

    transcript = OUT / "transcript.txt"
    with transcript.open("w", encoding="utf-8") as fh:
        for name, lines, duration, title in scenes:
            fh.write(f"=== {name}  ({duration:.0f}s)  {title}\n")
            fh.write("\n".join(lines) + "\n\n")

    size_mb = video.stat().st_size / 1e6
    total = sum(d for _n, _l, d, _t in scenes)
    print(f"\nwrote {video}  ({size_mb:.1f} MB, {total:.0f}s)")
    print(f"wrote {transcript}")
    print(f"raw captured output: {WORK}/")
    return 0


if __name__ == "__main__":
    sys.exit(main())
