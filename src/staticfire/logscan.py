"""Warnings and errors left in the logs during a run: the components' and the platform's.

A recipe can pass while a collector logs errors or the platform raises exceptions: this review
reads the component logs of the run and the platform log of its time window, and keeps each
distinct warning or error once, with how often it appeared.
"""

from __future__ import annotations

import json
import re
import subprocess
import time
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path

from staticfire import runner
from staticfire.config import Profile

LEVELS = ("WARNING", "WARN", "ERROR", "CRITICAL", "FATAL")
NOISE = re.compile(r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b|\d+")
# The containers whose logs make "the platform" of each (liftoff names them xtm-<service>-<n>)
PLATFORM_CONTAINERS = {
    "openaev": ["xtm-openaev-1"],
    # OpenCTI's workers ingest the connectors' bundles: their errors are the ingestion errors
    "opencti": ["xtm-opencti-1", "xtm-worker-1", "xtm-worker-2", "xtm-worker-3"],
}


def _normalise(message: str) -> str:
    """Group messages that only differ by ids and numbers."""
    return NOISE.sub("#", message)[:300]


def _component_entries(path: Path) -> list[tuple[str, str]]:
    entries = []
    traceback = False
    for line in path.read_text(errors="replace").splitlines():
        line = line.strip()
        if not line:
            continue
        if line.startswith("{"):
            try:
                record = json.loads(line)
            except ValueError:
                record = None
            if isinstance(record, dict):
                level = str(record.get("level", "")).upper()
                if level in LEVELS:
                    entries.append((level, str(record.get("message", ""))))
                traceback = False
                continue
        if line.startswith("Traceback"):
            traceback = True
            continue
        if traceback and re.match(r"^\w[\w.]*(Error|Exception)\b", line):
            entries.append(("ERROR", line))
            traceback = False
            continue
        match = re.search(r"\b(WARNING|ERROR|CRITICAL)\b", line)
        if match and not traceback:
            entries.append((match.group(1), line))
    return entries


def summarise(entries: list[tuple[str, str]], limit: int = 15) -> dict:
    counts = Counter((level, _normalise(message)) for level, message in entries)
    examples: dict[tuple[str, str], str] = {}
    for level, message in entries:
        examples.setdefault((level, _normalise(message)), message[:400])
    items = sorted(
        counts.items(), key=lambda kv: (kv[0][0] not in ("ERROR", "CRITICAL", "FATAL"), -kv[1])
    )
    return {
        "errors": sum(
            n for (level, _), n in counts.items() if level in ("ERROR", "CRITICAL", "FATAL")
        ),
        "warnings": sum(n for (level, _), n in counts.items() if level in ("WARNING", "WARN")),
        "distinct": [
            {"level": level, "count": n, "message": examples[(level, key)]}
            for (level, key), n in items[:limit]
        ],
    }


def component_logs_since(started_at: float) -> dict[str, dict]:
    """Every component log written since ``started_at`` (a run restarted many times has several)."""
    reviews = {}
    if not runner.RUNS_DIR.exists():
        return reviews
    for run_dir in sorted(runner.RUNS_DIR.iterdir()):
        logs = [p for p in sorted(run_dir.glob("*.log")) if p.stat().st_mtime + 1 >= started_at]
        if not logs:
            continue
        entries = [entry for path in logs for entry in _component_entries(path)]
        reviews[run_dir.name] = {"logs": [str(p) for p in logs], **summarise(entries)}
    return reviews


def _platform_entry(line: str) -> tuple[str, str] | None:
    """A WARN/ERROR record of the platform's JSON (logback) log, as (level, message)."""
    if not line.startswith("{"):
        return None
    try:
        record = json.loads(line)
    except ValueError:
        return None
    level = str(record.get("level", "")).upper()
    if level not in LEVELS:
        return None
    source = record.get("loggerName") or record.get("name") or record.get("category") or ""
    message = f"{source}: {record.get('message', '')}"
    throwable = record.get("throwable") or {}
    if throwable:
        message += f" [{throwable.get('className', '')}: {str(throwable.get('message', ''))[:200]}]"
    return level, message


def host_skew(profile: Profile) -> float:
    """The platform host's clock minus the local one, in seconds (0 when it cannot be read)."""
    try:
        result = subprocess.run(
            profile.remote_command("date +%s.%N"),
            capture_output=True,
            text=True,
            check=True,
            timeout=30,
        )
        return float(result.stdout.strip()) - time.time()
    except Exception:
        return 0.0


def platform_log_since(
    profile: Profile, started_at: float, skew: float = 0.0, platform: str = "openaev"
) -> dict:
    """The platform's warnings and errors since ``started_at`` (its containers' JSON logs).

    ``skew`` (platform clock minus local clock) shifts the window: docker filters on its own clock.
    """
    if not (profile.multipass_vm or profile.ssh_target):
        return {"skipped": "profile has no multipass_vm or ssh_target to read the platform log"}
    since = datetime.fromtimestamp(started_at + skew - 5, UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    entries = []
    for container in PLATFORM_CONTAINERS[platform]:
        command = f"sudo docker logs --since {since} {container} 2>&1"
        result = subprocess.run(
            profile.remote_command(command), capture_output=True, text=True, check=False, timeout=60
        )
        if result.returncode != 0:
            if container == PLATFORM_CONTAINERS[platform][0]:
                return {"skipped": f"cannot read the platform log: {result.stderr.strip()[:200]}"}
            continue  # fewer workers than expected
        entries += [e for line in result.stdout.splitlines() if (e := _platform_entry(line))]
    return summarise(entries)


def review(
    profile: Profile, started_at: float, skew: float = 0.0, platform: str = "openaev"
) -> dict:
    return {
        "components": component_logs_since(started_at),
        "platform": platform_log_since(profile, started_at, skew, platform),
    }


def one_line(logs: dict) -> str:
    """'components 0E/2W, platform 1E/0W' for summaries."""
    errors = sum(r.get("errors", 0) for r in logs.get("components", {}).values())
    warnings = sum(r.get("warnings", 0) for r in logs.get("components", {}).values())
    platform = logs.get("platform", {})
    if "skipped" in platform:
        return f"components {errors}E/{warnings}W, platform not read"
    return (
        f"components {errors}E/{warnings}W, "
        f"platform {platform.get('errors', 0)}E/{platform.get('warnings', 0)}W"
    )
