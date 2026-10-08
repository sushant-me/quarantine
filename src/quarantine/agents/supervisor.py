"""The supervisor: routes work between the agents and escalates what a human must decide.

The routing is a policy, not a prompt. Every branch below is a decision the *code* makes
from what the previous agent actually produced, and two of them exist purely to avoid the
worst possible outcome for a security gate — saying "fine" when we did not look:

1. **Nothing was observed** — the artifact could not be executed, or its weight format is
   one this reader cannot parse. We do not judge behaviour we did not observe; the case is
   escalated. (Before this rule existed, an artifact whose dependency was missing was
   reported ALLOW. That was a false negative in the most dangerous direction.)
2. **The agents disagree** — the analyst blocked, the challenger grounded a refutation.
   The supervisor does not pick a winner.
3. **The model was unreachable** — an outage must never become an ALLOW.

The turn budget is bounded: an agent loop that can run forever is not a control.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path

from quarantine.agents.blackboard import Blackboard
from quarantine.agents.case import Case
from quarantine.agents.roles import analyst, challenger, repairer
from quarantine.proof.equivalence import compare
from quarantine.sandbox.execute import run_trace
from quarantine.static.scan import static_pass

MAX_TURNS = 8


@dataclass
class Outcome:
    decided: str                      # ALLOW | BLOCK | UNKNOWN
    escalated: bool
    escalation_reason: str | None
    case: Case
    board: Blackboard
    analysis: dict | None = None
    challenge: dict | None = None
    repair: dict | None = None
    equivalence: dict | None = None
    turns: int = 0
    transcript: list[dict] = field(default_factory=list)

    def as_dict(self) -> dict:
        return {
            "decided": self.decided,
            "escalated": self.escalated,
            "escalation_reason": self.escalation_reason,
            "turns": self.turns,
            "agents": self.board.agents(),
            "case": self.case.summary(),
        }


def _declared(root: Path) -> str:
    readme = root / "README.md"
    return readme.read_text(encoding="utf-8") if readme.exists() else "(no README: nothing declared)"


def _shipped_code(root: Path, custom_files: list[str]) -> str:
    parts = []
    for rel in custom_files:
        path = root / rel
        if path.exists():
            parts.append(f"# ---- {rel} ----\n" + path.read_text(encoding="utf-8", errors="replace"))
    return "\n\n".join(parts) or "(no shipped Python code)"


def run_case(root: Path, out_dir: Path) -> Outcome:
    out_dir.mkdir(parents=True, exist_ok=True)
    board = Blackboard(out_dir / "board.jsonl")
    transcript: list[dict] = []

    # --- observer (deterministic) -----------------------------------------
    static = static_pass(root)
    (out_dir / "static.json").write_text(json.dumps(static, indent=2), encoding="utf-8")
    trace = run_trace(root, out_dir)
    case = Case(
        name=root.name,
        root=root,
        declared=_declared(root),
        code=_shipped_code(root, static.get("custom_code_files") or []),
        static=static,
        events=trace.get("events") or [],
        execution=trace.get("execution") or {},
    )
    board.post("observer", "observation", case.summary())
    turns = 1

    def escalate(reason: str, where: str = "supervisor") -> Outcome:
        board.post(where, "escalation", {"reason": reason, "routed_to": "human"})
        return Outcome("UNKNOWN", True, reason, case, board, turns=turns,
                       transcript=board.to_dict()["notes"])

    # --- route 1: was anything observed at all? ---------------------------
    reason = case.escalation_reason
    if reason:
        board.post("supervisor", "routing",
                   {"decision": "escalate", "why": "no behavioural observation is possible"})
        out = escalate(reason)
        return out

    # --- analyst (AI) ------------------------------------------------------
    analysis = analyst(case, board)
    turns += 1
    if analysis.get("error"):
        return escalate(f"the local model was unreachable ({analysis['error']}), "
                        "so no verdict was reached")

    verdict = analysis.get("verdict") or {}
    decided = verdict.get("verdict", "UNKNOWN")
    if decided in ("BLOCK", "ALLOW") and not analysis.get("grounded"):
        return escalate("the analyst's verdict was not grounded in the captured trace, "
                        "so it cannot be accepted")

    # --- route 2: adversarial check on a block -----------------------------
    challenge = None
    if decided == "BLOCK":
        challenge = challenger(case, board)
        turns += 1
        if challenge.get("refuted") and not challenge.get("admissible"):
            board.post("supervisor", "note", {
                "reason": "the challenger objected but could not ground it in the declaration",
                "quote_check": challenge.get("quote_check"),
                "quote_found_in_declaration": challenge.get("quote_found_in_declaration")})
        elif challenge.get("refuted") and challenge.get("admissible"):
            return escalate("the agents disagree: the analyst blocked and the challenger "
                            "grounded a refutation — "
                            f"{str(challenge.get('objection'))[:200]}")

    # --- repair (AI) then verify (deterministic) ---------------------------
    repair = None
    equivalence = None
    if decided == "BLOCK" and case.custom_files:
        repair = repairer(case, board)
        turns += 1
        if repair.get("code"):
            (out_dir / "loader_sanitized.py").write_text(repair["code"], encoding="utf-8")
        if repair.get("ok"):
            equivalence = compare(root / case.custom_files[0],
                                  out_dir / "loader_sanitized.py", out_dir)
            (out_dir / "equivalence.json").write_text(json.dumps(equivalence, indent=2),
                                                      encoding="utf-8")
            board.post("verifier", "equivalence", {
                "equivalent": equivalence["equivalent"],
                "prompts": equivalence["prompt_count"],
                "original_capability_ops": len(equivalence["original_capability_events"]),
                "sanitized_capability_ops": len(equivalence["sanitized_capability_events"]),
                "note": equivalence["note"],
            })
            turns += 1
    elif decided == "BLOCK":
        board.post("supervisor", "note",
                   {"reason": "blocked, but the artifact ships no Python to repair",
                    "detail": "repairing a weight-only payload means re-serialising it"})

    board.post("supervisor", "decision",
               {"decided": decided, "escalated": False, "turns": turns,
                "agents": board.agents()})
    return Outcome(decided, False, None, case, board, analysis, challenge, repair,
                   equivalence, turns, board.to_dict()["notes"])


def loader_sha256(outcome: Outcome) -> str | None:
    if outcome.repair and outcome.repair.get("code"):
        return hashlib.sha256(outcome.repair["code"].encode()).hexdigest()
    return None
