"""What the agents are looking at.

One object, assembled once, so every agent reasons over the same facts and the
supervisor can make routing decisions from what was actually observed rather than from
what a model claimed about it.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class Case:
    name: str
    root: Path
    declared: str = ""
    code: str = ""
    static: dict = field(default_factory=dict)
    events: list[dict] = field(default_factory=list)
    execution: dict = field(default_factory=dict)

    # ---- what was actually observed ---------------------------------------
    @property
    def custom_files(self) -> list[str]:
        return list(self.static.get("custom_code_files") or [])

    @property
    def executed(self) -> list[dict]:
        return list((self.execution or {}).get("executed") or [])

    @property
    def weights_loaded(self) -> list[dict]:
        return list((self.execution or {}).get("weights_loaded") or [])

    @property
    def weights_unreadable(self) -> list[dict]:
        return list((self.execution or {}).get("weights_unreadable") or [])

    @property
    def errors(self) -> list[str]:
        return list((self.execution or {}).get("errors") or [])

    @property
    def capability_events(self) -> list[dict]:
        from quarantine.events import capability_events
        return capability_events(self.events)

    @property
    def observed(self) -> bool:
        """Did we actually see the artifact do anything?

        Executing the shipped Python counts. Loading a plain pickle counts. **And so does a
        recorded capability operation** — an artifact that opens a socket and *then* dies has
        still been observed doing it, and refusing to judge that would throw away the best
        evidence in the case.

        A weight file this reader cannot parse does **not** count: a torch checkpoint is a zip
        containing a pickle that `torch.load` would unpickle, and not having read it means we
        have not looked at it at all.
        """
        return bool(self.executed or self.weights_loaded or self.capability_events)

    @property
    def code_path_unrun(self) -> bool:
        """Shipped Python exists, none of it ran, and we saw no capability from it.

        This is the partial-observation case, and it is dangerous in both directions. A real
        published model — `prajdabre/rotary-indictrans2-en-indic-dist-200M`, a custom
        architecture whose `modeling_*.py` imports torch — produced exactly this: the
        weights loaded, so the case looked "observed", while the code path that could carry
        a payload had never run. Not escalating let the analyst treat the resulting
        `ModuleNotFoundError` as evidence and **block a benign model**.
        """
        return bool(self.custom_files) and not self.executed and not self.capability_events

    @property
    def escalation_reason(self) -> str | None:
        """Why this case cannot be decided from behaviour, if it cannot."""
        if self.code_path_unrun:
            why = "; ".join(self.errors)[:200] if self.errors else "it did not run"
            return (f"the artifact's shipped Python ({', '.join(self.custom_files[:3])}) could not "
                    f"be executed ({why}), so the code path was never observed")
        if self.observed:
            return None
        if self.errors:
            return f"the artifact could not be executed ({'; '.join(self.errors)[:200]})"
        if self.weights_unreadable:
            why = self.weights_unreadable[0].get("why", "unknown format")
            return (f"nothing was observed: the weight file is not readable by this "
                    f"reader ({why}), so its contents were never examined")
        return "nothing in the artifact was executable or loadable, so nothing was observed"

    @property
    def capability_ids(self) -> list[int]:
        return [e["i"] for e in self.capability_events]

    def summary(self) -> dict:
        return {
            "name": self.name,
            "custom_files": self.custom_files,
            "events": len(self.events),
            "executed": [e.get("file") for e in self.executed],
            "weights_loaded": [e.get("file") for e in self.weights_loaded],
            "weights_unreadable": [e.get("file") for e in self.weights_unreadable],
            "capability_events": len(self.capability_events),
            "errors": self.errors,
            "observed": self.observed,
            "escalation_reason": self.escalation_reason,
        }
