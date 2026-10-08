# The demo video

| | |
|---|---|
| file | `quarantine-demo.mp4` — 1280×720, H.264, ~2 minutes, silent with on-screen captions |
| transcript | `transcript.txt` — the exact text of every frame, in order |
| raw capture | `session/` — the actual unedited output of every command the video shows |
| rebuild | `python scripts/build_demo_video.py` (needs `ffmpeg`, `magick`, and the model server for the live run) |

## What this is, stated precisely

**It is a replay rendered from real captured output — not a pixel capture of a screen.** There is no display
server on this machine, so a true screencast was not possible; saying "screen recording" when it is a replay
would be a small lie in a project whose entire argument is about evidence. The distinction is printed on the
closing frame as well.

What *is* real:

- every command output shown is the actual bytes the command produced (`session/` holds them unedited);
- the `quarantine inspect` run is executed live by the build script, not pasted;
- the evaluation numbers are read from `reports/corpus-eval.json` and `reports/corpus-real-eval.json`, which
  were produced by real runs over the labeled corpus and the four published models.

What is not:

- it has **no narration**. There is no English TTS voice on this machine (only `ne_NP`), and a synthetic
  voice would be worse than captions;
- it is **not** the final take. The script in [`docs/DEMO-SCRIPT.md`](../../docs/DEMO-SCRIPT.md) is written
  for a 3-minute narrated version, and every beat here maps onto it.

## Coverage against the script

| script beat | in the video |
|---|---|
| the scanner says clean | yes (live `picklescan` run) |
| the gap: shipped Python is not in its input set | yes |
| the artifact executes with the network off | yes (live trace) |
| the local model reads it and blocks | yes |
| repair + output-equivalence proof | yes |
| repair measured across the corpus, with the refusal stated | yes |
| measured numbers with a control group | yes (two tables) |
| containment, attacked on purpose | yes |
| the limits, said out loud | yes |
| narration | **no** — captions only |

## To make the narrated final take

Record the same commands with the script's narration over them. Nothing in the pipeline needs to change
except the audio track; the captions remain useful as subtitles.
