"""End-to-end recipes: fire a component at the real platform and check every observable effect.

Each recipe returns a Report (checks + verdict + refs + evidence). Recipes start the components
they need from their checkouts and stop them afterwards unless ``keep`` is set.
"""

from __future__ import annotations

import os
import uuid
from collections.abc import Callable
from pathlib import Path

from staticfire import ops, runner
from staticfire.config import Profile
from staticfire.report import Report

STATICFIRE_ROOT = Path(__file__).resolve().parents[2]
MAILPIT_COLLECTOR = STATICFIRE_ROOT / "collectors" / "mailpit"


def checkout(repo: str, name: str, path: str | None = None) -> str:
    """Locate a component checkout: explicit path, $STATICFIRE_<REPO>_DIR, or a sibling repo."""
    if path:
        return str(Path(path).expanduser())
    candidates = []
    if env := os.environ.get(f"STATICFIRE_{repo.upper()}_DIR"):
        candidates.append(Path(env) / name)
    candidates += [STATICFIRE_ROOT.parent / repo / name, Path.home() / "GitHub" / repo / name]
    for candidate in candidates:
        if (candidate / "pyproject.toml").exists():
            return str(candidate)
    raise FileNotFoundError(
        f"No {repo}/{name} checkout found (tried {[str(c) for c in candidates]}); pass its path"
    )


def _start(report: Report, profile: Profile, path: str, label: str, **kwargs) -> dict | None:
    up = ops.component_up(profile, path, **kwargs)
    report.refs[f"{label}_log"] = up["run"]["log"]
    if not report.check(
        f"{label} registers with the platform", up["registered"], up.get("log_tail")
    ):
        return None
    return up


def _email_content(profile: Profile, token: str) -> dict:
    return {
        "smtp_hostname": profile.smtp_host,
        "smtp_port": str(profile.smtp_port),
        "smtp_use_tls": False,
        "from": "staticfire@openaev.test",
        "to": f"{token}@staticfire.test",
        "cc": f"cc-{token}@staticfire.test",
        "subject": f"[staticfire {token}] email injector test",
        "body": f"staticfire probe {token}\nhttps://staticfire.test/{token}",
        "custom_headers": f"X-OpenAEV-Staticfire: {token}",
    }


def _check_delivery(report: Report, profile: Profile, content: dict, token: str) -> dict | None:
    box = ops.mailpit(profile)
    messages = box.wait_for(f'to:"{content["to"]}"', timeout=60)
    if not report.check("email delivered to mailpit", messages, f"nothing for {content['to']}"):
        return None
    mail = box.describe(messages[0]["ID"])
    report.evidence["email"] = mail
    report.refs["mailpit_message"] = f"{profile.mailpit_url}/view/{mail['id']}"
    report.check("sender", mail["from"] == content["from"], mail["from"])
    report.check(
        "recipients",
        content["to"] in mail["to"] and content["cc"] in mail["cc"],
        {"to": mail["to"], "cc": mail["cc"]},
    )
    report.check("subject", mail["subject"] == content["subject"], mail["subject"])
    report.check("body", token in (mail["text"] or ""), mail["text"])
    header = mail["custom_headers"].get("X-Openaev-Staticfire") or []
    report.check("custom header", header == [token], mail["custom_headers"])
    return mail


def email_smtp(
    profile: Profile,
    injector_path: str | None = None,
    pyoaev: str | None = None,
    keep: bool = False,
) -> Report:
    """Injector test: OpenAEV -> RabbitMQ -> email-smtp injector -> SMTP -> mailpit."""
    report = Report("email-smtp")
    path = checkout("injectors", "email-smtp", injector_path)
    run_name = "injector-email-smtp"
    try:
        up = _start(report, profile, path, "injector", pyoaev=pyoaev)
        if not up:
            return report
        contract = up["contracts"][0]
        report.refs["contract_id"] = contract["contract_id"]
        token = uuid.uuid4().hex[:10]
        content = _email_content(profile, token)
        result = ops.run_inject(
            profile, contract["contract_id"], content, title=f"staticfire email-smtp {token}"
        )
        report.refs["inject_id"] = result["inject_id"]
        report.refs["inject"] = result["link"]
        report.evidence["traces"] = result["traces"]
        report.check("inject finishes", result["finished"], result["status"])
        report.check("inject status EXECUTED", result["status"] == "EXECUTED", result["status"])
        report.check(
            "injector reports success",
            any(t["action"] == "COMPLETE" and t["status"] == "EXECUTED" for t in result["traces"]),
            result["traces"],
        )
        _check_delivery(report, profile, content, token)
    except Exception as err:
        report.error = f"{type(err).__name__}: {err}"
    finally:
        if report.verdict != "PASS":
            report.evidence["injector_log"] = _safe_tail(run_name)
        if not keep:
            runner.stop(run_name)
    return report


def mailpit_collector(
    profile: Profile,
    injector_path: str | None = None,
    collector_path: str | None = None,
    asset_id: str | None = None,
    keep: bool = False,
    timeout: float = 180,
) -> Report:
    """Collector test: an email inject with agent expectations, answered by a collector.

    The collector under test defaults to staticfire's mailpit collector; it must be one that
    answers email inject expectations from mailpit (pass collector_path to test another).
    """
    report = Report("mailpit-collector")
    injector = checkout("injectors", "email-smtp", injector_path)
    collector = collector_path or str(MAILPIT_COLLECTOR)
    runs = ["injector-email-smtp", f"collector-{Path(collector).name}"]
    try:
        endpoint = ops.agent_endpoint(profile, asset_id)
        report.refs["endpoint"] = f"{endpoint['name']} ({endpoint['asset_id']})"
        if not _start(report, profile, injector, "injector"):
            return report
        collector_up = _start(
            report,
            profile,
            collector,
            "collector",
            kind="collector",
            env={"MAILPIT_URL": profile.mailpit_url, "COLLECTOR_PERIOD": "10"},
        )
        if not collector_up:
            return report
        collector_id = collector_up["component"]["id"]
        token = uuid.uuid4().hex[:10]
        content = _email_content(profile, token)
        result = ops.run_inject(
            profile,
            ops.injector_contracts(profile, ops.resolve_injector(profile, injector))[0][
                "contract_id"
            ],
            content,
            assets=[endpoint["asset_id"]],
            expectations=list(ops.TECHNICAL_EXPECTATIONS),
            title=f"staticfire mailpit-collector {token}",
        )
        report.refs["inject_id"] = result["inject_id"]
        report.refs["inject"] = result["link"]
        report.check("inject status EXECUTED", result["status"] == "EXECUTED", result["status"])
        _check_delivery(report, profile, content, token)
        answered, expectations = ops.wait_expectations(
            profile, result["inject_id"], endpoint["asset_id"], collector_id, timeout=timeout
        )
        report.evidence["expectations"] = expectations
        report.check("collector answers every expectation in time", answered, expectations)
        by_type = {e["type"]: e for e in expectations}
        for kind, expected in (("DETECTION", "Detected"), ("PREVENTION", "Not Prevented")):
            mine = [
                r
                for r in (by_type.get(kind) or {}).get("results", [])
                if r["source_id"] == collector_id
            ]
            report.check(
                f"{kind} answered '{expected}' by the collector",
                bool(mine) and mine[0]["result"] == expected,
                mine,
            )
        detection = by_type.get("DETECTION")
        if detection and detection.get("id"):
            traces = ops.client(profile).expectation_traces(detection["id"], collector_id)
            report.evidence["detection_traces"] = traces
            report.check(
                "detection trace links the delivered message",
                any(token in (t.get("inject_expectation_trace_alert_name") or "") for t in traces),
                traces,
            )
    except Exception as err:
        report.error = f"{type(err).__name__}: {err}"
    finally:
        if report.verdict != "PASS":
            report.evidence["logs"] = {name: _safe_tail(name) for name in runs}
        if not keep:
            for name in runs:
                runner.stop(name)
    return report


def _safe_tail(run_name: str) -> str | None:
    try:
        return runner.tail(run_name, 40)
    except Exception:
        return None


RECIPES: dict[str, Callable[..., Report]] = {
    "email-smtp": email_smtp,
    "mailpit-collector": mailpit_collector,
}

DESCRIPTIONS = {
    "email-smtp": "Injector test: craft an email through the email-smtp injector, check that "
    "mailpit received it with the right sender, recipients, subject, body and header.",
    "mailpit-collector": "Collector test: an email inject with DETECTION/PREVENTION expectations "
    "on an agent endpoint, answered by the mailpit collector (Detected / Not Prevented).",
}
