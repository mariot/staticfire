"""Structured outcome of a staticfire run: named checks, a verdict and the evidence behind it."""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any


@dataclass
class Check:
    name: str
    ok: bool
    detail: Any = None


@dataclass
class Report:
    recipe: str
    started_at: float = field(default_factory=time.time)
    checks: list[Check] = field(default_factory=list)
    # Ids and links a human (or a model) needs to look further: inject id, UI links, mail ids...
    refs: dict[str, Any] = field(default_factory=dict)
    # Raw material backing the checks: execution traces, the delivered message, log excerpts...
    evidence: dict[str, Any] = field(default_factory=dict)
    error: str | None = None

    def check(self, name: str, ok: bool, detail: Any = None) -> bool:
        self.checks.append(Check(name, bool(ok), detail))
        return bool(ok)

    @property
    def verdict(self) -> str:
        if self.error:
            return "ERROR"
        return "PASS" if self.checks and all(c.ok for c in self.checks) else "FAIL"

    def to_dict(self) -> dict:
        return {
            "recipe": self.recipe,
            "verdict": self.verdict,
            "duration_s": round(time.time() - self.started_at, 1),
            "error": self.error,
            "checks": [{"name": c.name, "ok": c.ok, "detail": c.detail} for c in self.checks],
            "refs": self.refs,
            "evidence": self.evidence,
        }

    def summary(self) -> str:
        lines = [f"{self.recipe}: {self.verdict} ({round(time.time() - self.started_at, 1)}s)"]
        if self.error:
            lines.append(f"  error: {self.error}")
        for c in self.checks:
            mark = "ok  " if c.ok else "FAIL"
            detail = f" - {c.detail}" if c.detail not in (None, "") and not c.ok else ""
            lines.append(f"  [{mark}] {c.name}{detail}")
        for key, value in self.refs.items():
            lines.append(f"  {key}: {value}")
        return "\n".join(lines)
