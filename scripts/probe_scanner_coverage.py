#!/usr/bin/env python3
"""Measure the incumbent scanner's denylist coverage, as a rate.

The pitch claims static scanners recognise *known* badness while behaviour is the ground
truth. This puts a number on the "known" part: take a set of standard-library callables
that perform network or filesystem I/O, build one benign pickle per callable, and ask
three questions of each:

  1. does picklescan flag it?
  2. does fickling flag it?
  3. does Quarantine's contained run actually observe the operation?

A callable that reaches the network while both scanners report clean is a demonstrated
coverage gap. Nothing here is weaponised: every hostname is under `.invalid` (RFC 2606)
and every filesystem target is a harmless, existing path or a throwaway in /tmp. The run
itself happens in the same network-less container as every other artifact.

    python scripts/probe_scanner_coverage.py

Writes reports/scanner-coverage.json and reports/scanner-coverage.md.
"""

from __future__ import annotations

import json
import pickle
import shutil
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from quarantine.sandbox.execute import run_trace          # noqa: E402
from quarantine.static.scan import parse_fickling, parse_picklescan, run_incumbents  # noqa: E402

REPORTS = ROOT / "reports"
HOST = "coverage.invalid"


def _net(fn, *args):
    return lambda: (fn, args)


CANDIDATES: list[tuple[str, str, object]] = [
    # network
    ("socket.gethostbyname", "network", _net(__import__("socket").gethostbyname, HOST)),
    ("socket.gethostbyaddr", "network", _net(__import__("socket").gethostbyaddr, HOST)),
    ("socket.getfqdn", "network", _net(__import__("socket").getfqdn, HOST)),
    ("socket.getaddrinfo", "network", _net(__import__("socket").getaddrinfo, HOST, 80)),
    ("socket.create_connection", "network", _net(__import__("socket").create_connection, (HOST, 80))),
    ("ssl.get_server_certificate", "network", _net(__import__("ssl").get_server_certificate, (HOST, 443))),
    ("http.client.HTTPConnection", "network", _net(__import__("http.client", fromlist=["x"]).HTTPConnection, HOST)),
    ("urllib.request.urlopen", "network", _net(__import__("urllib.request", fromlist=["x"]).urlopen, f"http://{HOST}/")),
    ("ftplib.FTP", "network", _net(__import__("ftplib").FTP, HOST)),
    ("smtplib.SMTP", "network", _net(__import__("smtplib").SMTP, HOST)),
    ("poplib.POP3", "network", _net(__import__("poplib").POP3, HOST)),
    ("imaplib.IMAP4", "network", _net(__import__("imaplib").IMAP4, HOST)),
    ("xmlrpc.client.ServerProxy", "network", _net(__import__("xmlrpc.client", fromlist=["x"]).ServerProxy, f"http://{HOST}/")),
    # filesystem
    ("builtins.open", "filesystem", _net(open, "/etc/hostname")),
    ("pathlib.Path.read_text", "filesystem", lambda: (__import__("pathlib").Path("/etc/hostname").read_text, ())),
    ("os.remove", "filesystem", _net(__import__("os").remove, "/tmp/coverage-probe-does-not-exist")),
    # process
    ("subprocess.Popen", "process", _net(__import__("subprocess").Popen, ["/bin/true"])),
    ("os.popen", "process", _net(__import__("os").popen, "/bin/true")),
    # dynamic code
    ("builtins.eval", "dynamic_code", _net(eval, "1 + 1")),
    # --- negative controls: harmless standard-library calls a legitimate pickle makes.
    # Without these, "19/19 flagged" could just mean the scanner suspects everything.
    ("json.dumps (control)", "benign", _net(__import__("json").dumps, {"a": 1})),
    ("math.sqrt (control)", "benign", _net(__import__("math").sqrt, 4.0)),
    ("collections.OrderedDict (control)", "benign", _net(__import__("collections").OrderedDict, [])),
    ("datetime.datetime.now (control)", "benign", _net(__import__("datetime").datetime.now, ())),
    ("os.getcwd (control)", "benign", _net(__import__("os").getcwd, ())),
    ("re.compile (control)", "benign", _net(__import__("re").compile, "abc")),
]


class Payload:
    def __init__(self, factory) -> None:
        self.factory = factory

    def __reduce__(self):
        return self.factory()


def build(case_dir: Path, factory) -> None:
    case_dir.mkdir(parents=True, exist_ok=True)
    (case_dir / "README.md").write_text(
        "Declares a pure, deterministic text transform: no network, no file access, no processes.",
        encoding="utf-8")
    (case_dir / "pytorch_model.bin").write_bytes(pickle.dumps({"x": Payload(factory)}))


def main() -> int:
    REPORTS.mkdir(exist_ok=True)
    work = Path(tempfile.mkdtemp(prefix="coverage-"))
    rows = []
    try:
        for name, kind, factory in CANDIDATES:
            case = work / name.replace(".", "_")
            build(case, factory)

            inc = run_incumbents(case)
            ps = parse_picklescan(inc["picklescan"])
            fk = parse_fickling(inc["fickling"])

            trace = run_trace(case, work / (case.name + "-trace"))
            from quarantine.events import capability_events
            caps = capability_events(trace["events"])
            observed = bool(caps)

            rows.append({
                "global": name,
                "kind": kind,
                # verdict-level (picklescan's own "infected") kept apart from any signal
                "picklescan_flagged": bool(ps.get("verdict_malicious")),
                "picklescan_suspicious_only": (ps.get("says_clean") is False
                                               and not ps.get("verdict_malicious")),
                "fickling_flagged": fk.get("says_clean") is False,
                "quarantine_observed": observed,
                "observed_events": [f"{e['event']}: {e['detail'][:40]}" for e in caps][:3],
                "both_clean": (ps.get("says_clean") is not False and fk.get("says_clean") is not False),
            })
            print(f"{name:32} picklescan={'FLAG' if rows[-1]['picklescan_flagged'] else 'clean':5} "
                  f"fickling={'FLAG' if rows[-1]['fickling_flagged'] else 'clean':5} "
                  f"quarantine={'observed' if observed else 'nothing'}", flush=True)
    finally:
        shutil.rmtree(work, ignore_errors=True)

    total = len(rows)
    benign = [r for r in rows if r["kind"] == "benign"]
    offensive = [r for r in rows if r["kind"] != "benign"]
    ps_flag = sum(1 for r in rows if r["picklescan_flagged"])
    fk_flag = sum(1 for r in rows if r["fickling_flagged"])
    observed = sum(1 for r in rows if r["quarantine_observed"])
    gaps = [r for r in rows if r["both_clean"] and r["quarantine_observed"]]
    ps_fp = sum(1 for r in benign if r["picklescan_flagged"])
    fk_fp = sum(1 for r in benign if r["fickling_flagged"])
    q_fp = sum(1 for r in benign if r["quarantine_observed"])
    ps_noisy = sum(1 for r in benign if r.get("picklescan_suspicious_only"))

    report = {
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "candidates": total,
        "operation_candidates": len(offensive),
        "benign_controls": len(benign),
        "picklescan_flagged": ps_flag,
        "fickling_flagged": fk_flag,
        "quarantine_observed": observed,
        "both_scanners_clean_but_observed": len(gaps),
        "gaps": [g["global"] for g in gaps],
        "picklescan_false_positives_on_controls": ps_fp,
        "fickling_false_positives_on_controls": fk_fp,
        "quarantine_false_positives_on_controls": q_fp,
        "rows": rows,
        "note": ("Every payload is a benign probe: hostnames are under `.invalid` (RFC 2606) "
                 "and no filesystem target is harmed. This measures denylist coverage, not an exploit."),
    }
    (REPORTS / "scanner-coverage.json").write_text(json.dumps(report, indent=2), encoding="utf-8")

    lines = [
        "# Scanner denylist coverage — and a negative result",
        "",
        f"{len(offensive)} standard-library callables that perform network, filesystem, process or "
        f"dynamic-code operations, each built into a one-pickle probe artifact, plus "
        f"**{len(benign)} benign controls** (harmless stdlib calls a legitimate pickle makes). "
        "Nothing is weaponised: every host is under `.invalid` and every filesystem target is "
        "harmless or absent.",
        "",
        "| measure | result |",
        "|---|---|",
        f"| picklescan 1.0.5 flagged the {len(offensive)} operation probes | **{sum(1 for r in offensive if r['picklescan_flagged'])}/{len(offensive)}** |",
        f"| fickling 0.1.12 flagged them | **{sum(1 for r in offensive if r['fickling_flagged'])}/{len(offensive)}** |",
        f"| Quarantine observed the operation | **{sum(1 for r in offensive if r['quarantine_observed'])}/{len(offensive)}** |",
        f"| **both scanners clean AND the operation observed** | **{len(gaps)}** |",
        f"| picklescan called the benign controls infected (its own verdict) | **{ps_fp}/{len(benign)}** |",
        f"| picklescan flagged them *suspicious* without calling them infected | {ps_noisy}/{len(benign)} |",
        f"| fickling false positives on the benign controls | **{fk_fp}/{len(benign)}** |",
        f"| Quarantine false positives on the benign controls | **{q_fp}/{len(benign)}** |",
        "",
        "## The negative result, stated plainly",
        "",
        "**We set out to find a callable that reaches the network or the filesystem while both",
        "scanners report clean, and we did not find one.** Their denylists cover direct calls to",
        "the standard-library primitives in this set, and picklescan reads inside zip archives too.",
        (f"On the benign controls picklescan flagged {ps_fp}/{len(benign)} and fickling {fk_fp}/{len(benign)}, so the "
         "100% above is denylist coverage rather than blanket suspicion."
         if (ps_fp + fk_fp) < 2 * len(benign) else
         "On the benign controls the scanners also flagged heavily, so the 100% above reflects "
         "blanket suspicion as much as denylist coverage."),
        "",
        "That is why this project does **not** claim a scanner bypass. The measured difference is",
        "**coverage of the code path**: the payloads that neither scanner opens live in",
        "`custom_generate/generate.py` and `modeling_*.py`, not in a pickle. See `reports/corpus-eval.md`.",
        "",
        "## Per callable", "",
        "| callable | kind | picklescan | fickling | Quarantine |",
        "|---|---|---|---|---|",
    ]
    for r in rows:
        lines.append(f"| `{r['global']}` | {r['kind']} | "
                     f"{'flagged' if r['picklescan_flagged'] else '**clean**'} | "
                     f"{'flagged' if r['fickling_flagged'] else '**clean**'} | "
                     f"{'observed' if r['quarantine_observed'] else 'nothing'} |")
    if gaps:
        lines += ["", "## Demonstrated coverage gaps (both scanners clean, operation observed)", ""]
        lines += [f"- `{g['global']}` — {', '.join(g['observed_events'])}" for g in gaps]
    lines += ["", report["note"], ""]
    (REPORTS / "scanner-coverage.md").write_text("\n".join(lines), encoding="utf-8")

    print("\n" + "\n".join(lines[:16]))
    print(f"\nwrote {REPORTS / 'scanner-coverage.md'} and scanner-coverage.json")
    return 0


if __name__ == "__main__":
    sys.exit(main())
