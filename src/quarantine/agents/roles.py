"""The agents and what each is for.

Three roles use the local model and three are deterministic. The split is deliberate:
a model decides what the evidence *means*; code decides what was observed and whether a
claim is admissible. No agent's output is taken on trust — every one is either grounded
against the trace or checked by a deterministic verifier.

    analyst     decides ALLOW / BLOCK / UNKNOWN from the declaration plus the trace
    challenger  tries to REFUTE the analyst, using the same evidence
    repairer    writes a replacement for the offending function bodies

    observer    (deterministic) runs the artifact contained and records the trace
    verifier    (deterministic) output-equivalence + zero-capability check
    scribe      (deterministic) assembles and signs the receipt

The challenger exists because a single model's verdict is not evidence. If it can
ground a refutation, the case is escalated to a human instead of the supervisor
silently picking a winner.
"""

from __future__ import annotations

import time

from quarantine.agents.blackboard import Blackboard
from quarantine.agents.case import Case
from quarantine.events import capability_events
from quarantine.llm import ModelUnreachable, chat
from quarantine.repair.loader import forbidden_in_source, synthesize_loader
from quarantine.semantic.analyst import analyse_artifact

CHALLENGE_SCHEMA = {
    "type": "object",
    "properties": {
        "refuted": {"type": "boolean"},
        "objection": {"type": "string"},
        "permitting_quote": {"type": "string"},
        "evidence_ids": {"type": "array", "items": {"type": "integer"}},
        "confidence": {"type": "number"},
    },
    "required": ["refuted", "objection", "permitting_quote", "evidence_ids", "confidence"],
}

CHALLENGE_SYSTEM = (
    "You are the challenger. Another analyst has reached a verdict about a model "
    "artifact and cited evidence. Your job is to REFUTE it if you honestly can. "
    "Rules: (1) only the trace events listed exist - never cite an id that is not in the "
    "list; (2) to refute, you must quote VERBATIM from the declared behaviour the sentence "
    "that permits the operation the analyst objected to - if no such sentence exists, you "
    "cannot refute, and you must set refuted to false; (3) copying a sentence that does not "
    "permit the operation is not a refutation. Answer with JSON only."
)


def _normalise(text: str) -> str:
    return " ".join(text.lower().split())


# A sentence that forbids the operation cannot be the sentence that permits it. Without this,
# "is the quote really from the declaration" and "does the quote permit the behaviour" collapse
# into one check, and the model can overturn a correct block by quoting the rule it broke: on
# our own labeled corpus it quoted "must not read files outside its own directory" and the
# text-membership check accepted it. Rejecting is the safe direction - a refutation that cannot
# be established leaves the analyst's block standing.
_PROHIBITION = ("must not", "may not", "should not", "cannot", "can not", "never", "no ",
                "not permitted", "forbidden", "prohibited", "disallow", "without")


def _quote_supports_refutation(quote: str, declared: str) -> tuple[bool, str]:
    """Does the quoted sentence come from the declaration *and* permit the operation?

    The challenger's objection may only overturn a verdict if it points at the actual text.
    A model can otherwise object plausibly while citing real trace ids — which is exactly what
    happened the first time this agent ran: it claimed the declaration permitted a DNS lookup,
    on an artifact whose declaration forbids the network.
    """
    q, d = _normalise(quote), _normalise(declared)
    if len(q) < 15:
        return False, "quote too short to be a sentence from the declaration"
    if any(marker in q for marker in _PROHIBITION):
        return False, "the quoted sentence forbids the operation, so it cannot permit it"
    if q in d:
        return True, "verbatim match in the declaration"
    words = [w for w in q.split() if len(w) > 3]
    if words:
        overlap = sum(1 for w in words if w in d) / len(words)
        if overlap >= 0.8:
            return True, f"{overlap:.0%} of the quoted words appear in the declaration"
    return False, "the quoted sentence does not appear in the declaration"


def analyst(case: Case, board: Blackboard) -> dict:
    """AI #1 — the verdict, grounded against the captured trace."""
    started = time.time()
    try:
        result = analyse_artifact(case.declared, case.code, case.events, case.static,
                                  execution=case.execution)
    except ModelUnreachable as exc:
        board.post("analyst", "error", {"reason": str(exc)})
        return {"verdict": None, "error": str(exc), "elapsed_s": round(time.time() - started, 2)}
    board.post("analyst", "verdict", {
        "verdict": (result.get("verdict") or {}).get("verdict"),
        "grounded": result.get("grounded"),
        "cited_ids": result.get("cited_ids"),
        "mechanism": (result.get("verdict") or {}).get("mechanism", "")[:300],
        "rounds": result.get("rounds"),
        "elapsed_s": result.get("elapsed_s"),
    })
    result["elapsed_s"] = round(time.time() - started, 2)
    return result


def challenger(case: Case, board: Blackboard) -> dict:
    """AI #2 — tries to refute the analyst, and may only succeed by quoting the declaration.

    **This function did not do that until it was fixed.** The file held two `challenger`
    definitions; Python runs the last one, and the rule below lived in the first — so the
    advertised behaviour was dead code, `_quote_supports_refutation` was called by nothing, and
    the supervisor's `challenge.get("admissible")` check could never be true. The
    "agents disagree" escalation was unreachable while the README, the AI-usage disclosure, the
    deck and the business case all described it. A duplicate definition is not a style problem;
    it is how a feature stops existing without anything failing.
    """
    started = time.time()
    verdict = board.latest("verdict") or {}
    ids = [e["i"] for e in case.events]
    trace_lines = "\n".join(f"  id={e['i']:>3} {e['event']}: {e['detail']}"
                            for e in case.events) or "  (no events captured)"
    caps = [(e["i"], e["event"], e["detail"]) for e in capability_events(case.events)]
    user = (
        f"=== DECLARED BEHAVIOUR ===\n{case.declared.strip()[:1000]}\n\n"
        f"=== THE ANALYST'S VERDICT ===\n"
        f"  verdict: {verdict.get('verdict')}\n"
        f"  mechanism: {verdict.get('mechanism', '')[:400]}\n"
        f"  cited ids: {verdict.get('cited_ids')}\n\n"
        f"=== THE ONLY EVIDENCE THAT EXISTS ===\n{trace_lines[:1800]}\n\n"
        f"  capability events: {caps}\n"
        f"  valid ids: {ids}\n\n"
        "Can the verdict be refuted from this evidence? If yes, quote the sentence in the "
        "DECLARED BEHAVIOUR that permits the operation, verbatim. Answer with JSON only."
    )
    try:
        _raw, parsed = chat([{"role": "system", "content": CHALLENGE_SYSTEM},
                             {"role": "user", "content": user}], schema=CHALLENGE_SCHEMA,
                            max_tokens=350)
    except ModelUnreachable as exc:
        board.post("challenger", "error", {"reason": str(exc)})
        return {"refuted": False, "admissible": False, "grounded": False, "error": str(exc),
                "elapsed_s": round(time.time() - started, 2)}

    parsed = parsed or {}
    cited = parsed.get("evidence_ids") or []
    ids_ok = all(isinstance(i, int) and i in ids for i in cited)
    refuted = bool(parsed.get("refuted"))
    quote = str(parsed.get("permitting_quote", ""))
    quote_ok, quote_why = _quote_supports_refutation(quote, case.declared)

    # A refutation needs BOTH halves, and neither is the model's to grant: the evidence it cites
    # must exist, and the sentence it quotes must actually be in the declaration. "I cannot
    # refute it" needs neither.
    admissible = bool(ids_ok and quote_ok) if refuted else True
    result = {
        "refuted": refuted,
        "admissible": admissible,
        # `grounded` is kept as the same value because it is what the board and the CLI display:
        # an objection is "grounded" when it survives the harness's checks, not when the model
        # claims it does. The two were different before this fix, which is how the display came
        # to print grounded=True on an objection the supervisor was rejecting.
        "grounded": admissible,
        "objection": str(parsed.get("objection", ""))[:400],
        "permitting_quote": quote[:300],
        "quote_found_in_declaration": quote_ok,
        "quote_check": quote_why,
        "evidence_ids": cited,
        "evidence_ids_valid": ids_ok,
        "confidence": parsed.get("confidence"),
        "valid_ids": ids,
        "elapsed_s": round(time.time() - started, 2),
    }
    board.post("challenger", "objection", result)
    return result


def repairer(case: Case, board: Blackboard) -> dict:
    """AI #3 — writes the replacement bodies; the harness assembles the file."""
    started = time.time()
    verdict = (board.latest("verdict") or {})
    try:
        result = synthesize_loader(case.declared, case.code, verdict)
    except ModelUnreachable as exc:
        board.post("repairer", "error", {"reason": str(exc)})
        return {"attempted": True, "ok": False, "code": None, "error": str(exc)}
    result["attempted"] = True
    board.post("repairer", "repair", {
        "ok": result.get("ok"),
        "attempts": len(result.get("attempts") or []),
        "removed": result.get("removed"),
        "forbidden_remaining": result.get("forbidden"),
        "loader_sha256": (__import__("hashlib").sha256(result["code"].encode()).hexdigest()
                          if result.get("code") else None),
        "elapsed_s": result.get("elapsed_s"),
    })
    result["elapsed_s"] = round(time.time() - started, 2)
    return result


__all__ = ["analyst", "challenger", "repairer", "forbidden_in_source", "Case", "Blackboard"]
