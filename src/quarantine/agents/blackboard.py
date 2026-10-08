"""The case file the agents work on — append-only, on disk.

Agents do not talk to each other directly. Each one reads the board, adds a note, and
returns; the supervisor decides who runs next from what is on the board. That keeps the
hand-offs inspectable after the fact: a receipt can carry the whole transcript, and a
human can see exactly which agent said what, in order.

Append-only JSONL, for the same reason the receipt is signed: a record that can be
quietly rewritten is not evidence.
"""

from __future__ import annotations

import datetime as dt
import json
from pathlib import Path


class Blackboard:
    def __init__(self, path: Path) -> None:
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._notes: list[dict] = []

    # ---- writing -----------------------------------------------------------
    def post(self, agent: str, kind: str, content: dict) -> dict:
        note = {
            "seq": len(self._notes) + 1,
            "at": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
            "agent": agent,
            "kind": kind,
            "content": content,
        }
        self._notes.append(note)
        with self.path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(note) + "\n")
        return note

    # ---- reading -----------------------------------------------------------
    def of_kind(self, kind: str) -> list[dict]:
        return [n for n in self._notes if n["kind"] == kind]

    def latest(self, kind: str) -> dict | None:
        found = self.of_kind(kind)
        return found[-1]["content"] if found else None

    def agents(self) -> list[str]:
        seen: list[str] = []
        for note in self._notes:
            if note["agent"] not in seen:
                seen.append(note["agent"])
        return seen

    def to_dict(self) -> dict:
        return {"notes": self._notes, "agents": self.agents()}
