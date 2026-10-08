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
import urllib.error
import urllib.request

from quarantine.events import capability_events
from quarantine.modelinfo import resolve_model

VERDICT_SCHEMA = {
    "type": "object",
    "properties": {
        "verdict": {"type": "string", "enum": ["ALLOW", "BLOCK", "UNKNOWN"]},
        "declared_matches_behaviour": {"type": "boolean"},
        "mechanism": {"type": "string"},
        "evidence_ids": {"type": "array", "items": {"type": "integer"}},
        "confidence": {"type": "number"},
    },
    "required": ["verdict", "declared_matches_behaviour", "mechanism", "evidence_ids", "confidence"],
}

SYSTEM = (
    "You are a model-artifact security analyst. You compare what an artifact DECLARES "
    "with what it actually DID, using only the evidence given to you. "
    "Rules: (1) evidence_ids must list trace ids that literally appear in the trace below - "
    "never invent an id; (2) if the trace shows the artifact performing an operation its "
    "declaration forbids, the verdict is BLOCK; (3) if the trace shows no such operation, the "
    "verdict is ALLOW; (4) if the evidence is insufficient, the verdict is UNKNOWN. "
    "A trace with no capability events means nothing suspicious happened. Reply with JSON only."
)

URL = os.environ.get("QUARANTINE_MODEL_URL", "http://127.0.0.1:8081/v1/chat/completions")
MODEL = os.environ.get("QUARANTINE_MODEL_NAME", "qwen2.5-1.5b-instruct-q4_k_m")


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
    find_lines = "\n".join(
        f"  {f['file']}:{f['line']} {f['capability']} -> {f['call']}" for f in findings
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
        f"=== STATIC FINDINGS ===\n{find_lines}\n\n"
        "=== DECISION PROCEDURE ===\n"
        f"  Step 0: if ANYTHING OBSERVED is false, nothing was run and the verdict is UNKNOWN. "
        "You cannot judge behaviour you did not observe.\n"
        f"  Step 1: the harness says there are {len(cap_ids)} capability events and "
        f"{len(unresolved)} unresolved globals.\n"
        "  Step 2: if capability events is 0 AND unresolved globals is 0, nothing suspicious "
        "happened and the verdict is ALLOW with declared_matches_behaviour=true and "
        "evidence_ids=[] — even if serialization helpers were stubbed, and even if [context] "
        "lines mention files, imports or temporary directories. [context] lines are never a "
        "reason to answer UNKNOWN.\n"
        "  Step 3: if capability events is greater than 0, decide whether the DECLARED behaviour "
        "permits each one. If any is not permitted by the declaration, the verdict is BLOCK and "
        "evidence_ids must list the ids of the capability events you rely on.\n"
        "  Step 4: answer UNKNOWN only when the observation is genuinely partial "
        "(unresolved globals > 0) or the evidence does not fit the two cases above.\n"
        "Answer with JSON only."
    )


def _post(payload: dict, timeout: int = 180) -> dict:
    req = urllib.request.Request(URL, data=json.dumps(payload).encode(),
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode())


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
    out: dict = {"model": MODEL, "reachable": False, "grounded": False, "raw": None}

    # Two rounds: if the model cites evidence that does not exist, it is told exactly
    # which ids are valid and asked again. An ungrounded verdict is never accepted.
    for round_no in range(MAX_ROUNDS):
        candidates = [
            {"model": MODEL, "messages": messages, "temperature": 0.0, "max_tokens": 400,
             "stream": False,
             "response_format": {"type": "json_schema",
                                 "json_schema": {"name": "verdict", "schema": VERDICT_SCHEMA}}},
            {"model": MODEL, "messages": messages, "temperature": 0.0, "max_tokens": 400,
             "stream": False, "response_format": {"type": "json_object"}},
            {"model": MODEL, "messages": messages, "temperature": 0.0, "max_tokens": 400,
             "stream": False},
        ]
        parsed, text = None, ""
        for payload in candidates:
            try:
                body = _post(payload)
            except (urllib.error.URLError, TimeoutError, OSError) as exc:
                out["error"] = f"{type(exc).__name__}: {exc}"
                out["elapsed_s"] = round(time.time() - started, 2)
                return out
            out["reachable"] = True
            text = body.get("choices", [{}])[0].get("message", {}).get("content", "")
            out["raw"] = text
            parsed = _parse_json(text)
            if parsed:
                break
        if not parsed:
            break

        cited = parsed.get("evidence_ids") or []
        verdict_name = parsed.get("verdict")
        caps = capability_events(events)
        cap_ids = {e["i"] for e in caps}
        grounded = verdict_is_grounded(verdict_name, cited, valid_ids, cap_ids)

        out.update({"verdict": parsed, "cited_ids": cited, "grounded": grounded,
                    "valid_ids": sorted(valid_ids), "rounds": round_no + 1,
                    "capability_events": [e["i"] for e in caps]})
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

    out["model"] = resolve_model(MODEL)
    out["elapsed_s"] = round(time.time() - started, 2)
    return out
