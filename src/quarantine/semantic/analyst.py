"""The semantic pass — the first place AI is load-bearing.

The model is given the artifact's *declared* behaviour, its *shipped* code, the
captured behavioural trace and the static capability map, and must return a
schema-constrained verdict whose evidence it cites by trace id or file:line.

Two rules keep this honest:

1. The model never decides alone. It reasons over a trace it did not produce.
2. The verdict is only accepted if it is *grounded*: every evidence id it cites
   must exist in the trace, **and a BLOCK must cite at least one capability event**.
   An execution error is not evidence of capability — it means we could not look.
   An ungrounded verdict is recorded as such and the
   caller degrades it to UNKNOWN. Nothing is coerced.
"""

from __future__ import annotations

import json
import os
import time

import quarantine.llm as llm
from quarantine.events import capability_events
from quarantine.modelinfo import resolve_model

# The ground a verdict rests on, as a closed vocabulary rather than free text.
#
# This exists because a 7B model, given the harness's own counters, answered UNKNOWN with the
# mechanism "unresolved globals" on an artifact whose unresolved-globals count was ZERO and
# whose capability count was zero - a case the written procedure says must be ALLOW. The
# sentence was in a free-text field, so nothing could contradict it. Now the ground is chosen
# from a list, and the harness checks the choice against the numbers it counted itself.
REASONS = (
    "nothing_observed",        # observed, nothing capability-like happened      -> ALLOW
    "capability_observed",     # a capability happened that the declaration bars  -> BLOCK
    "nothing_run",             # the code path never ran                          -> UNKNOWN
    "counters_incomplete",     # unresolved globals make the observation partial  -> UNKNOWN
    "evidence_ambiguous",      # the evidence fits none of the above              -> UNKNOWN
)

REASON_VERDICT = {
    "nothing_observed": "ALLOW",
    "capability_observed": "BLOCK",
    "nothing_run": "UNKNOWN",
    "counters_incomplete": "UNKNOWN",
    "evidence_ambiguous": "UNKNOWN",
}

# There is deliberately no "capability_permitted" ground. The policy is that an observed
# capability is never allowed: `verdict_is_grounded` requires zero capability events for ALLOW,
# so a ground meaning "it happened but the declaration allows it" describes an outcome this
# system cannot produce. It was in the first draft of this vocabulary and the 3B model chose it
# for four benign artifacts that had zero capability events — a label for an impossible state,
# which turned four correct ALLOWs into rejected ones. Removing it is a correction, not a
# concession: the vocabulary should only name states the machine can actually be in.


VERDICT_SCHEMA = {
    "type": "object",
    "properties": {
        "verdict": {"type": "string", "enum": ["ALLOW", "BLOCK", "UNKNOWN"]},
        "declared_matches_behaviour": {"type": "boolean"},
        "mechanism": {"type": "string"},
        "evidence_ids": {"type": "array", "items": {"type": "integer"}},
        "confidence": {"type": "number"},
        "reason": {"type": "string", "enum": list(REASONS)},
    },
    "required": ["verdict", "declared_matches_behaviour", "mechanism", "evidence_ids",
                 "confidence", "reason"],
}

# The enum is not decoration. llama.cpp compiles a JSON schema into a grammar, so an enum
# constrains what the model can *emit*: with the valid trace ids enumerated, a hallucinated
# citation is impossible rather than merely rejected afterwards. This was measured — asked
# outright to cite ids 161/166/248 on a 25-event trace, the model could only produce ids
# that were in the enum. Before this, a real third-party model was escalated because the
# analyst answered BLOCK citing ids that did not exist.
MAX_ENUM_IDS = 200
MAX_EVIDENCE_IDS = 8

def reason_is_admissible(reason: str | None, verdict_name: str | None, cap_count: int,
                         unresolved_count: int, observed: bool) -> tuple[bool, str]:
    """Is the stated ground factually available on this evidence?

    **This checks claims about the counters, not labels about the verdict.** The harness owns
    the counters; the model owns the judgement. A ground that asserts a condition the harness
    counted as absent is rejected, because that is how a model abstains by asserting a false
    premise. A ground that merely picks an imprecise label for a correct verdict is not
    rejected — an earlier version of this function did that, and it cost a real published model
    its ALLOW: `bert-tiny` answered ALLOW with a mechanism that read "further supporting the
    ALLOW verdict", the label was rejected, and three retries degraded a correct answer into an
    UNKNOWN. Rejecting a correct decision over a word is worse than accepting a loose word.

    So the rules are only about what the harness counted:

    * `counters_incomplete` asserts unresolved globals exist — rejected when none were counted.
    * `nothing_run` asserts the artifact never ran — rejected when the harness watched it run.
    * `capability_observed` asserts a capability happened — rejected when none was counted.
    * `nothing_observed` asserts nothing happened and nothing is unresolved — likewise checked.

    The verdict is deliberately not compared against the reason. `evidence_ambiguous` is always
    admissible: an honest abstention must stay available, or the rule would abolish abstention
    rather than validate it.
    """
    if reason is None:
        return True, "no reason stated"
    if reason not in REASONS:
        return False, f"{reason!r} is not one of the grounds the harness defines"
    if reason == "counters_incomplete" and unresolved_count == 0:
        return False, ("the reason is counters_incomplete but the harness counted 0 unresolved "
                       "globals, so that ground is not available")
    if reason == "nothing_run" and observed:
        return False, ("the reason is nothing_run but the harness observed the artifact running")
    if reason == "capability_observed" and cap_count == 0:
        return False, ("the reason is capability_observed but the harness counted 0 capability "
                       "events")
    if reason == "nothing_observed" and (cap_count or unresolved_count or not observed):
        return False, (f"the reason is nothing_observed but the harness counted {cap_count} "
                       f"capability events, {unresolved_count} unresolved globals, "
                       f"observed={observed}")
    return True, "admissible"


def verdict_schema(valid_ids: list[int]) -> dict:
    """The verdict schema, with the admissible evidence constrained to the real trace ids."""
    schema = json.loads(json.dumps(VERDICT_SCHEMA))
    ids = sorted({i for i in valid_ids if isinstance(i, int)})
    if 0 < len(ids) <= MAX_ENUM_IDS:
        schema["properties"]["evidence_ids"] = {
            "type": "array",
            "items": {"enum": ids},
            "maxItems": MAX_EVIDENCE_IDS,      # also grammar-enforced: no degenerate 45-item loops
        }
    return schema

SYSTEM = (
    "You are a model-artifact security analyst. You compare what an artifact DECLARES "
    "with what it actually DID, using only the evidence given to you. "
    "Rules: (1) evidence_ids must list trace ids that literally appear in the trace below - "
    "never invent an id; (2) if the trace shows the artifact performing an operation its "
    "declaration forbids, the verdict is BLOCK; (3) if the trace shows no such operation, the "
    "verdict is ALLOW; (4) if the evidence is insufficient, the verdict is UNKNOWN. "
    "A trace with no capability events means nothing suspicious happened. Reply with JSON only."
)

def _prompt(declared: str, code: str, events: list[dict], static: dict,
            execution: dict | None = None) -> str:
    # Mark every trace line as evidence or context, decided by the harness rather than by
    # the model. Without the marker a real, benign model (the IndicTrans2 custom
    # architecture) was abstained on because the model read a context event — torch's own
    # import noise — as something the artifact had done.
    cap_set = {e["i"] for e in capability_events(events)}
    trace_lines = "\n".join(
        f"  id={e['i']:>3} [{'EVIDENCE' if e['i'] in cap_set else 'context '}] "
        f"{e['event']}: {e['detail']}"
        for e in events
    ) or "  (no events captured)"
    cap_ids = sorted(cap_set)
    static_caps = static.get("capability_graph", {}).get("capabilities", {})
    cap_lines = ", ".join(f"{k}={v}" for k, v in static_caps.items() if v) or "none"
    findings = static.get("capability_graph", {}).get("findings", [])[:25]
    observed_findings = sum(
        1 for f in findings
        if f.get("call") and any(f["call"] in str(e.get("detail", "")) for e in events)
    )
    # Deliberately NOT `file:line`. That format printed numbers like
    # `tokenization_indictrans.py:161`, and the analyst cited 161/166/248 as *trace ids* — it
    # was reading source line numbers as evidence ids. It looked like hallucination and was a
    # prompt-design defect: two namespaces printed in the same shape.
    find_lines = "\n".join(
        f"  {f['file']} (source line {f['line']}): {f['capability']} -> {f['call']}"
        for f in findings
    ) or "  (none)"
    ex = execution or {}
    executed = [e.get("file") for e in (ex.get("executed") or [])]
    loaded = [e.get("file") for e in (ex.get("weights_loaded") or [])]
    unreadable = [e.get("file") for e in (ex.get("weights_unreadable") or [])]
    errors = ex.get("errors") or []
    observed = bool(executed or loaded)
    stubbed = [e for e in events if e.get("event") == "weights.stubbed"]
    unresolved = [e for e in events if e.get("event") == "weights.unresolved"]
    return (
        f"=== DECLARED BEHAVIOUR (what the artifact claims) ===\n{declared.strip()[:1000]}\n\n"
        f"=== SHIPPED CODE (executed on load) ===\n{code.strip()[:2200]}\n\n"
        f"=== BEHAVIOURAL TRACE (captured, network off) ===\n"
        "  Every line is marked by the harness. [context] lines are the interpreter and its\n"
        "  libraries doing ordinary work - they are NOT evidence and must not be cited.\n"
        f"{trace_lines[:2200]}\n\n"
        f"=== OBSERVATION STATUS (computed by the harness, not by you) ===\n"
        f"  shipped Python executed: {executed or 'none'}\n"
        f"  plain/zip pickles loaded: {loaded or 'none'}\n"
        f"  weight files unreadable:  {unreadable or 'none'}\n"
        f"  execution errors:         {errors or 'none'}\n"
        f"  ANYTHING OBSERVED:        {observed}\n"
        f"  serialization helpers stubbed: {len(stubbed)} "
        "(tensor-rebuild scaffolding. It cannot open a socket or read a file, and it does "
        "NOT make the observation partial. Do not answer UNKNOWN because of these.)\n"
        f"  UNRESOLVED globals: {len(unresolved)} "
        "(these DO make the observation partial — the code path could not run as written)\n\n"
        f"=== CAPABILITY EVENT COUNT (computed by the harness, not by you) ===\n"
        f"  {len(cap_ids)} of {len(events)} trace events are capability events. ids={cap_ids}\n\n"
        f"=== STATIC CAPABILITY COUNTS ===\n{cap_lines}\n\n"
        f"=== STATIC FINDINGS (what the code COULD do — not what it did) ===\n{find_lines}\n"
        f"  {len(findings)} static finding(s); {observed_findings} of them appear in the trace. "
        "These are source-level possibilities, not observations.\n\n"
        "=== DECISION PROCEDURE ===\n"
        f"  Step 0: if ANYTHING OBSERVED is false, nothing was run and the verdict is UNKNOWN. "
        "You cannot judge behaviour you did not observe.\n"
        f"  Step 1: the harness says there are {len(cap_ids)} capability events and "
        f"{len(unresolved)} unresolved globals.\n"
        "  Step 2: if capability events is 0 AND unresolved globals is 0, the verdict is ALLOW "
        "with declared_matches_behaviour=true and evidence_ids=[]. This holds even if "
        "serialization helpers were stubbed, even if [context] lines mention files, imports or "
        "temporary directories, and — importantly — even if the STATIC FINDINGS above name "
        "capabilities such as open() or socket(). The static findings are a map of what the code "
        "COULD do; the capability count is a record of what it DID. This tool exists because "
        "those are different questions and behaviour is the ground truth. A source file that "
        "mentions open() while performing zero file reads outside its own directory, in a box "
        "with the network off, has not done anything its declaration forbids.\n"
        "  Step 3: if capability events is greater than 0, the verdict is BLOCK and evidence_ids "
        "must list the ids of the capability events you rely on. Whether the declaration would "
        "permit such a capability is not yours to allow: an observed capability is never an ALLOW "
        "in this system, and the challenger and repairer handle that question after you.\n"
        "  Step 4: answer UNKNOWN only when the observation is genuinely partial "
        "(unresolved globals > 0) or the evidence is genuinely ambiguous.\n"
        "\n=== THE GROUND YOU MUST STATE ===\n"
        "  Every answer states `reason`, chosen from this list. The harness checks it against its\n"
        "  own counts, and an answer whose ground is unavailable is rejected.\n"
        "    nothing_observed      capability events = 0 and anything was observed   -> ALLOW\n"
        "    capability_observed   capability events > 0, declaration does not permit -> BLOCK\n"
        "    nothing_run           the code path never ran                            -> UNKNOWN\n"
        "    counters_incomplete   unresolved globals make the observation partial    -> UNKNOWN\n"
        "    evidence_ambiguous    the evidence fits none of the above                 -> UNKNOWN\n"
        "  Do not claim counters_incomplete unless the harness counted unresolved globals > 0, and\n"
        "  do not claim nothing_run if it observed the artifact running. If the capability count is\n"
        "  zero and anything was observed, the ground is nothing_observed - there is no ground for an\n"
        "  allowed capability, because an observed capability is never allowed here.\n"
        "Answer with JSON only."
    )


def _parse_json(text: str) -> dict | None:
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass
    start, end = text.find("{"), text.rfind("}")
    if start != -1 and end > start:
        try:
            return json.loads(text[start:end + 1])
        except json.JSONDecodeError:
            pass
    return None


MAX_ROUNDS = 3


def verdict_is_grounded(verdict_name: str | None, cited: list, valid_ids: set,
                        cap_ids: set) -> bool:
    """Is this verdict admissible, given what the harness independently observed?

    The three rules, all of them deterministic and none of them the model's to make:

    * **BLOCK** must cite at least one *capability event*. Citing an id that merely exists is
      not enough — an execution error is not evidence of capability, and treating it as such
      blocked a benign real published model whose custom code raised `ModuleNotFoundError`.
    * **ALLOW** is admissible only when the harness counted **zero** capability events.
    * **UNKNOWN** needs no evidence; it is the honest abstention.

    A cited id that does not exist makes any verdict ungrounded.
    """
    if not all(isinstance(i, int) and i in valid_ids for i in cited):
        return False
    if verdict_name == "BLOCK":
        return bool(cited) and any(i in cap_ids for i in cited)
    if verdict_name == "ALLOW":
        return not cap_ids
    return True


def analyse_artifact(declared: str, code: str, events: list[dict], static: dict,
                     execution: dict | None = None) -> dict:
    """Return {verdict, grounded, raw, model, elapsed_s, reachable}."""
    started = time.time()
    valid_ids = {e["i"] for e in events}
    messages = [
        {"role": "system", "content": SYSTEM},
        {"role": "user", "content": _prompt(declared, code, events, static, execution)},
    ]
    out: dict = {"model": llm.MODEL, "reachable": False, "grounded": False, "raw": None}

    # Up to MAX_ROUNDS: if the model cites evidence that does not exist, it is told exactly
    # which ids are valid and asked again. An ungrounded verdict is never accepted.
    #
    # The call goes through `llm.chat` rather than a private copy of the HTTP client. It used
    # to have its own URL and model constants, which quietly falsified the AI-usage
    # disclosure's claim that `src/quarantine/llm.py::chat` is the one place that talks to the
    # model — and it made a "delete the AI" measurement silently measure nothing, because
    # patching the shared endpoint had no effect on this file.
    for round_no in range(MAX_ROUNDS):
        try:
            text, parsed = llm.chat(messages, schema=verdict_schema(sorted(valid_ids)),
                                    max_tokens=400)
        except llm.ModelUnreachable as exc:
            out["error"] = str(exc)
            out["elapsed_s"] = round(time.time() - started, 2)
            return out
        out["reachable"] = True
        out["raw"] = text
        if parsed is None:
            parsed = _parse_json(text)
        if not parsed:
            break

        cited = parsed.get("evidence_ids") or []
        verdict_name = parsed.get("verdict")
        caps = capability_events(events)
        cap_ids = {e["i"] for e in caps}
        ex = execution or {}
        observed = bool((ex.get("executed") or []) or (ex.get("weights_loaded") or []))
        unresolved = [e for e in events if e.get("event") == "weights.unresolved"]
        reason = parsed.get("reason")
        reason_ok, reason_why = reason_is_admissible(
            reason, verdict_name, len(caps), len(unresolved), observed)
        available = [r for r in REASONS
                     if reason_is_admissible(r, verdict_name, len(caps), len(unresolved),
                                             observed)[0]]
        # The ground is recorded and annotated, and it does NOT veto the verdict.
        #
        # A first version ANDed reason_ok into grounded, so an unavailable ground rejected the
        # answer. It was measured over two models and eleven artifacts, and it never once
        # changed a decision for the better:
        #   * the 7B still abstained on the artifacts that motivated the rule - three retries
        #     did not correct it;
        #   * the 3B lost a correct ALLOW (it labelled an ALLOW "capability_permitted" on an
        #     artifact with no capability events) and then escalated `benign-unicode` after the
        #     retries failed, taking the corpus from 0 escalations to 1.
        # So the load-bearing check stays the one that is about evidence ids, and the ground is
        # carried into the receipt as an annotation an auditor can read: reason, reason_ok,
        # reason_why, admissible_reasons. A false ground is now visible rather than decisive.
        grounded = verdict_is_grounded(verdict_name, cited, valid_ids, cap_ids)

        out.update({"verdict": parsed, "cited_ids": cited, "grounded": grounded,
                    "valid_ids": sorted(valid_ids), "rounds": round_no + 1,
                    "capability_events": [e["i"] for e in caps],
                    "reason": reason, "reason_ok": reason_ok, "reason_why": reason_why,
                    "admissible_reasons": available})
        if grounded or not valid_ids or round_no == MAX_ROUNDS - 1:
            break

        ids_ok = all(isinstance(i, int) and i in valid_ids for i in cited)
        if not ids_ok:
            feedback = (f"Your evidence_ids {cited} are not all real trace ids. The only valid ids "
                        f"are {sorted(valid_ids)}. Answer again, citing only ids from that list.")
        elif verdict_name == "BLOCK":
            # The block was grounded in nothing: it cited ids that exist but no capability
            # event. Saying so is more useful than repeating the whole prompt.
            feedback = (f"You answered BLOCK but cited {cited}, and none of those ids is a capability "
                        f"event. Your evidence_ids MUST include at least one of these ids: "
                        f"{[e['i'] for e in caps]} - they are the capability events, and they are what "
                        "the declaration is compared against. If none of them is unexplained by the "
                        "declared behaviour, the verdict cannot be BLOCK. Answer again.")
        else:
            feedback = (f"You answered ALLOW, but the captured trace contains capability events "
                        f"{[e['i'] for e in caps]} that the declaration does not allow: "
                        f"{[(e['i'], e['event']) for e in caps]}. If they are not explained by the "
                        "declared behaviour, the verdict cannot be ALLOW.")
        messages = messages + [
            {"role": "assistant", "content": text[:600]},
            {"role": "user", "content": feedback + " Answer again with JSON only."},
        ]

    out["model"] = resolve_model(llm.MODEL)
    out["elapsed_s"] = round(time.time() - started, 2)
    return out
