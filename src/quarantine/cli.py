"""Quarantine CLI — the whole loop, one command.

    python -m quarantine.cli inspect corpus/probe-custom-generate --out runs/probe
    python -m quarantine.cli verify  runs/probe/receipt.json --pub keys/quarantine.pub.pem
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import sys
from pathlib import Path

from quarantine.proof.equivalence import compare
from quarantine.receipt import generate_keypair, verify_receipt, sign_receipt
from quarantine.repair.loader import synthesize_loader
from quarantine.sandbox.execute import IMAGE, run_trace
from quarantine.semantic.analyst import MODEL, analyse_artifact
from quarantine.static.scan import static_pass

VERSION = "0.1.0-spike"


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _declared(root: Path) -> str:
    readme = root / "README.md"
    return readme.read_text(encoding="utf-8") if readme.exists() else "(no README: nothing declared)"


def _shipped_code(root: Path, custom_files: list[str]) -> str:
    parts = []
    for rel in custom_files:
        p = root / rel
        if p.exists():
            parts.append(f"# ---- {rel} ----\n" + p.read_text(encoding="utf-8", errors="replace"))
    return "\n\n".join(parts) or "(no shipped Python code)"


def cmd_inspect(args: argparse.Namespace) -> int:
    root = Path(args.artifact).resolve()
    out = Path(args.out).resolve() if args.out else (Path.cwd() / "runs" / root.name)
    out.mkdir(parents=True, exist_ok=True)
    print(f"[1/6] static pass           {root}")

    static = static_pass(root)
    (out / "static.json").write_text(json.dumps(static, indent=2), encoding="utf-8")
    caps = {k: v for k, v in static["capability_graph"]["capabilities"].items() if v}
    iv = static["incumbent_verdict"]
    print(f"      picklescan: scanned={iv['picklescan']['scanned_files']} "
          f"clean={iv['picklescan']['says_clean']} | "
          f"fickling: scanned={iv['fickling']['scanned_files']} clean={iv['fickling']['says_clean']}")
    print(f"      static capabilities: {caps or 'none'}")

    print("[2/6] behavioural pass       executing, network off")
    trace = run_trace(root, out)
    print(f"      container rc={trace['returncode']}  events={trace['event_count']}")
    for e in trace["events"][:6]:
        print(f"        id={e['i']:>3} {e['event']}: {e['detail'][:70]}")

    print("[3/6] semantic pass          local open-weight model")
    declared = _declared(root)
    code = _shipped_code(root, static["custom_code_files"])
    analysis = analyse_artifact(declared, code, trace["events"], static)
    (out / "verdict.json").write_text(json.dumps(analysis, indent=2), encoding="utf-8")
    verdict = analysis.get("verdict") or {}
    print(f"      reachable={analysis['reachable']} grounded={analysis['grounded']} "
          f"verdict={verdict.get('verdict')} in {analysis.get('elapsed_s')}s")
    if verdict.get("mechanism"):
        print(f"      mechanism: {verdict['mechanism'][:110]}")

    decided = verdict.get("verdict", "UNKNOWN")
    if decided in ("BLOCK", "ALLOW") and not analysis["grounded"]:
        decided = "UNKNOWN"
        print("      -> verdict was ungrounded (evidence or cross-check failed); recorded as UNKNOWN")

    custom_files = static["custom_code_files"]
    print("[4/6] repair pass            local open-weight model")
    repair = {"attempted": False, "ok": False, "code": None}
    if decided == "BLOCK" and custom_files:
        repair = synthesize_loader(declared, code, verdict)
        repair["attempted"] = True
        if repair.get("code"):
            (out / "loader_sanitized.py").write_text(repair["code"], encoding="utf-8")
        print(f"      generated={bool(repair.get('code'))} ok={repair.get('ok')} "
              f"forbidden={repair.get('forbidden')} in {repair.get('elapsed_s')}s")
        if repair.get("error"):
            print(f"      error: {repair['error'][:110]}")
    elif decided == "BLOCK":
        # A pickle-only artifact ships no Python to rewrite. Repairing it means
        # re-serialising the weights (safetensors), which is a different operation —
        # so we say so instead of inventing a loader or crashing on an empty list.
        repair["skipped_reason"] = "no shipped Python to repair (payload is a weight file)"
        print(f"      skipped: {repair['skipped_reason']}")
    else:
        print("      skipped (no grounded BLOCK)")

    print("[5/6] equivalence proof")
    equivalence = {"equivalent": False, "note": "not attempted"}
    if repair.get("attempted") and repair.get("ok") and custom_files:
        original = root / custom_files[0]
        equivalence = compare(original, out / "loader_sanitized.py", out)
        (out / "equivalence.json").write_text(json.dumps(equivalence, indent=2), encoding="utf-8")
        print(f"      equivalent={equivalence['equivalent']} over {equivalence['prompt_count']} prompts; "
              f"capability ops original={len(equivalence['original_capability_events'])} "
              f"repaired={len(equivalence['sanitized_capability_events'])}")
        if not equivalence["equivalent"]:
            print(f"      rejected: {equivalence['note'][:110]}")
    else:
        (out / "equivalence.json").write_text(json.dumps(equivalence, indent=2), encoding="utf-8")
        print("      skipped (no verified repair)")

    print("[6/6] sign receipt")
    keys = Path(args.keys).resolve() if args.keys else (out / "keys")
    key_path = keys / "quarantine.pem"
    if not key_path.exists():
        pub = generate_keypair(key_path)
        print(f"      new keypair -> {pub}")
    pub_path = key_path.with_suffix(".pub.pem")

    trace_bytes = (out / "trace.jsonl").read_bytes() if (out / "trace.jsonl").exists() else b""
    payload = {
        "spec": "quarantine/receipt/v0",
        "generated_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "artifact": {
            "name": root.name,
            "tree_sha256": static["inventory"]["tree_sha256"],
            "file_count": static["inventory"]["file_count"],
        },
        "static": {
            "capabilities": static["capability_graph"]["capabilities"],
            "findings": static["capability_graph"]["findings"][:50],
            "incumbent_verdict": static["incumbent_verdict"],
        },
        "behaviour": {
            "event_count": trace["event_count"],
            "trace_sha256": _sha256_bytes(trace_bytes),
            "events": trace["events"],
            "execution": trace.get("execution", {}),
            "container": {"image": IMAGE, "network": "none", "read_only": True,
                          "cap_drop": "ALL", "no_new_privileges": True},
        },
        "verdict": {"decided": decided, "grounded": analysis["grounded"],
                    "model_output": verdict, "cited_ids": analysis.get("cited_ids", [])},
        "repair": {"attempted": repair.get("attempted", False), "ok": repair.get("ok", False),
                   "forbidden_remaining": repair.get("forbidden", []),
                   "loader_sha256": (_sha256_bytes(repair["code"].encode())
                                     if repair.get("code") else None),
                   "removed": repair.get("removed", [])},
        "equivalence": equivalence,
        "model": {"name": analysis.get("model", MODEL), "name_server_reported": True,
                  "repair_model": repair.get("model"), "roles": ["semantic", "repair"],
                  "hosting": "local llama.cpp", "repair_assembled_by": repair.get("assembled_by")},
        "tool": {"name": "quarantine", "version": VERSION},
    }
    envelope = sign_receipt(payload, key_path)
    (out / "receipt.json").write_text(json.dumps(envelope, indent=2), encoding="utf-8")
    ok = verify_receipt(envelope, pub_path)
    print(f"      signed and verified: {ok}  keyid={envelope['signatures'][0]['keyid']}")

    print("\n=== Quarantine verdict ===")
    print(f"  artifact          {root.name}")
    print(f"  incumbents        picklescan clean={static['incumbent_verdict']['picklescan']['says_clean']} "
          f"fickling clean={static['incumbent_verdict']['fickling']['says_clean']} "
          f"(custom Python scanned: no)")
    print(f"  behavioural trace {trace['event_count']} events, network=none")
    print(f"  verdict           {decided}  (grounded={analysis['grounded']})")
    print(f"  repair            ok={repair.get('ok', False)} equivalent={equivalence.get('equivalent')}")
    print(f"  receipt           {out / 'receipt.json'}  verified={ok}")
    return 0


def cmd_verify(args: argparse.Namespace) -> int:
    envelope = json.loads(Path(args.receipt).read_text(encoding="utf-8"))
    pub = Path(args.pub)
    ok = verify_receipt(envelope, pub)
    print(f"receipt {args.receipt}: signature valid = {ok}")
    if ok:
        payload = json.loads(__import__("base64").b64decode(envelope["payload"]))
        print(f"  artifact  {payload['artifact']['name']}  tree={payload['artifact']['tree_sha256'][:16]}")
        print(f"  verdict   {payload['verdict']['decided']}  grounded={payload['verdict']['grounded']}")
        print(f"  repair    ok={payload['repair']['ok']} equivalent={payload['equivalence'].get('equivalent')}")
    return 0 if ok else 1


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="quarantine", description=__doc__)
    sub = parser.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("inspect", help="run the full loop on an artifact")
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
