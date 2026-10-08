"""Quarantine CLI — one command runs the whole agent team.

    python -m quarantine.cli inspect corpus/probe-custom-generate --out runs/probe
    python -m quarantine.cli verify  runs/probe/receipt.json --pub keys/quarantine.pub.pem

Exit codes are a policy, not a detail — they are what makes this usable as a gate:

    0   ALLOW      nothing the artifact did contradicts what it declared
    1   BLOCK      the artifact did something its declaration forbids
    2   UNKNOWN    nothing was observed, the agents disagreed, or the model was down

**2 is not 0.** The whole point of the escalation path is that "we could not look" must
never be reported as "it is fine".
"""

from __future__ import annotations

import argparse
import base64
import datetime as dt
import json
import sys
from pathlib import Path

from quarantine.agents.supervisor import loader_sha256, run_case
from quarantine.events import baseline_info
from quarantine.llm import served_model
from quarantine.receipt import generate_keypair, sign_receipt, verify_receipt
from quarantine.sandbox.execute import IMAGE

VERSION = "0.2.0-agents"
EXIT_CODE = {"ALLOW": 0, "BLOCK": 1, "UNKNOWN": 2}


def _render_board(notes: list[dict]) -> None:
    """Print what the agents actually did, from the board rather than from narration."""
    for note in notes:
        kind, agent, content = note["kind"], note["agent"], note["content"]
        if kind == "observation":
            print(f"[1/4] observer    {content['events']} events, network=none; "
                  f"executed={content['executed'] or 'none'}; observed={content['observed']}")
        elif kind == "routing":
            print(f"      supervisor  -> {content['decision']} ({content['why']})")
        elif kind == "escalation":
            print(f"[!]   ESCALATED   {content['reason']}")
        elif kind == "verdict":
            print(f"[2/4] analyst     {content['verdict']} grounded={content['grounded']} "
                  f"cited={content['cited_ids']} in {content['elapsed_s']}s")
            if content.get("mechanism"):
                print(f"      mechanism   {content['mechanism'][:110]}")
        elif kind == "objection":
            print(f"[3/4] challenger  refuted={content['refuted']} "
                  f"grounded={content['grounded']} in {content['elapsed_s']}s")
            if content.get("objection"):
                print(f"      objection   {content['objection'][:110]}")
        elif kind == "repair":
            print(f"[4/4] repairer    ok={content['ok']} removed={content['removed']} "
                  f"in {content['elapsed_s']}s")
        elif kind == "equivalence":
            print(f"      verifier    equivalent={content['equivalent']} over {content['prompts']} "
                  f"prompts; capability ops {content['original_capability_ops']} -> "
                  f"{content['sanitized_capability_ops']}")
        elif kind == "note":
            print(f"      supervisor  {content['reason']}")


def cmd_inspect(args: argparse.Namespace) -> int:
    root = Path(args.artifact).resolve()
    out = Path(args.out).resolve() if args.out else (Path.cwd() / "runs" / root.name)
    out.mkdir(parents=True, exist_ok=True)

    outcome = run_case(root, out)
    _render_board(outcome.transcript)

    case = outcome.case
    keys = Path(args.keys).resolve() if args.keys else (out / "keys")
    key_path = keys / "quarantine.pem"
    if not key_path.exists():
        pub = generate_keypair(key_path)
        print(f"      keypair     -> {pub.name}")
    pub_path = key_path.with_suffix(".pub.pem")

    trace_bytes = (out / "trace.jsonl").read_bytes() if (out / "trace.jsonl").exists() else b""
    payload = {
        "spec": "quarantine/receipt/v1",
        "generated_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "artifact": {
            "name": root.name,
            "tree_sha256": case.static["inventory"]["tree_sha256"],
            "file_count": case.static["inventory"]["file_count"],
        },
        "static": {
            "capabilities": case.static["capability_graph"]["capabilities"],
            "findings": case.static["capability_graph"]["findings"][:50],
            "incumbent_verdict": case.static["incumbent_verdict"],
            "shipped_python_files": case.custom_files,
        },
        "behaviour": {
            "event_count": len(case.events),
            "trace_sha256": __import__("hashlib").sha256(trace_bytes).hexdigest(),
            "events": case.events,
            "execution": case.execution,
            "container": {"image": IMAGE, "network": "none", "read_only": True,
                          "cap_drop": "ALL", "no_new_privileges": True},
            "noise_floor": baseline_info(IMAGE),
        },
        "verdict": {
            "decided": outcome.decided,
            "escalated": outcome.escalated,
            "escalation_reason": outcome.escalation_reason,
            "grounded": (outcome.analysis or {}).get("grounded"),
            "model_output": (outcome.analysis or {}).get("verdict"),
            "cited_ids": (outcome.analysis or {}).get("cited_ids", []),
            # The ground the model stated, and whether it survives the harness's own counters.
            # It is an annotation rather than a veto, because enforcing it was measured to cost
            # correct decisions and to save none - see SPIKE-RESEARCH.md section 3f. An auditor
            # reading a receipt can now see not only what was decided but on what stated ground.
            "stated_reason": (outcome.analysis or {}).get("reason"),
            "reason_consistent_with_counters": (outcome.analysis or {}).get("reason_ok"),
            "reason_note": (outcome.analysis or {}).get("reason_why"),
            "challenge": outcome.challenge,
        },
        "repair": {
            "attempted": (outcome.repair or {}).get("attempted", False),
            "ok": (outcome.repair or {}).get("ok", False),
            "forbidden_remaining": (outcome.repair or {}).get("forbidden", []),
            "removed": (outcome.repair or {}).get("removed", []),
            "loader_sha256": loader_sha256(outcome),
            "skipped_reason": (outcome.repair or {}).get("skipped_reason"),
        },
        "equivalence": outcome.equivalence or {"equivalent": False, "note": "not attempted"},
        "agents": {
            "team": outcome.board.agents(),
            "turns": outcome.turns,
            "escalated_to_human": outcome.escalated,
            "transcript": outcome.transcript,
        },
        "model": {"name": served_model(), "name_server_reported": True,
                  "roles": ["analyst", "challenger", "repairer"], "hosting": "local llama.cpp"},
        "tool": {"name": "quarantine", "version": VERSION},
    }
    envelope = sign_receipt(payload, key_path)
    (out / "receipt.json").write_text(json.dumps(envelope, indent=2), encoding="utf-8")
    verified = verify_receipt(envelope, pub_path)

    print("\n=== Quarantine verdict ===")
    print(f"  artifact          {root.name}")
    inc = case.static["incumbent_verdict"]
    print(f"  incumbents        picklescan clean={inc['picklescan']['says_clean']} "
          f"fickling clean={inc['fickling']['says_clean']} (custom Python scanned: no)")
    print(f"  behavioural trace {len(case.events)} events, network=none, observed={case.observed}")
    print(f"  verdict           {outcome.decided}"
          + (f"  (ESCALATED: {outcome.escalation_reason[:80]})" if outcome.escalated else ""))
    eq = outcome.equivalence or {}
    print(f"  repair            ok={(outcome.repair or {}).get('ok', False)} "
          f"equivalent={eq.get('equivalent', False)}")
    print(f"  agents            {', '.join(outcome.board.agents())} in {outcome.turns} turns")
    print(f"  receipt           {out / 'receipt.json'}  verified={verified}")
    print(f"  exit code         {EXIT_CODE[outcome.decided]} "
          f"({outcome.decided} — 0 allow, 1 block, 2 unknown)")
    return EXIT_CODE[outcome.decided]


def cmd_verify(args: argparse.Namespace) -> int:
    envelope = json.loads(Path(args.receipt).read_text(encoding="utf-8"))
    ok = verify_receipt(envelope, Path(args.pub))
    print(f"receipt {args.receipt}: signature valid = {ok}")
    if ok:
        payload = json.loads(base64.b64decode(envelope["payload"]))
        print(f"  artifact  {payload['artifact']['name']}  tree={payload['artifact']['tree_sha256'][:16]}")
        print(f"  verdict   {payload['verdict']['decided']}"
              + ("  (escalated)" if payload['verdict'].get('escalated') else ""))
        print(f"  agents    {', '.join(payload.get('agents', {}).get('team', []))}")
        print(f"  repair    ok={payload['repair']['ok']} "
              f"equivalent={payload['equivalence'].get('equivalent')}")
    return 0 if ok else 1


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="quarantine", description=__doc__)
    sub = parser.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("inspect", help="run the agent team on an artifact")
    p.add_argument("artifact")
    p.add_argument("--out", default=None)
    p.add_argument("--keys", default=None)
    p.set_defaults(func=cmd_inspect)
    v = sub.add_parser("verify", help="verify a receipt independently")
    v.add_argument("receipt")
    v.add_argument("--pub", required=True)
    v.set_defaults(func=cmd_verify)
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
