"""End-to-end recipes: fire a component at the real platform and check every observable effect.

Each recipe returns a Report (checks + verdict + refs + evidence). Recipes start the components
they need from their checkouts and stop them afterwards unless ``keep`` is set.
"""

from __future__ import annotations

import os
import time
import uuid
from collections.abc import Callable
from pathlib import Path

from staticfire import fakes, ops, runner
from staticfire.config import Profile
from staticfire.openaev import wait_until
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
                if r["source_id"] == collector_id and r["result"]
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


XDR_ALERTS_PATH = "/palo-alto-cortex-xdr/public_api/v1/alerts/get_alerts_multi_events"
XDR_VERDICTS = {
    # verdict -> (alerts the fake XDR returns, result expected per expectation type)
    "prevented": (
        ["Detected (Reported)", "Prevented (Blocked)"],
        {"DETECTION": "Detected", "PREVENTION": "Prevented"},
    ),
    "detected": (["Detected (Reported)"], {"DETECTION": "Detected", "PREVENTION": None}),
    "none": ([], {"DETECTION": None, "PREVENTION": None}),
}


def _xdr_alert(alert_id: int, implant: str, action_pretty: str, timestamp_ms: int) -> dict:
    return {
        "external_id": f"staticfire-{alert_id}",
        "severity": "high",
        "matching_status": "MATCHED",
        "case_id": None,
        "alert_id": alert_id,
        "actor_process_command_line": implant,
        "category": "Malware",
        "description": "Alert scripted by staticfire",
        "action": action_pretty.split(" ")[0].upper(),
        "action_pretty": action_pretty,
        "detection_timestamp": timestamp_ms,
        # The implant in the events lets the collector match without enrichment calls
        "events": [{"actor_process_image_name": implant}],
    }


def cortex_xdr(
    profile: Profile,
    collector_path: str | None = None,
    verdict: str = "prevented",
    asset_id: str | None = None,
    keep: bool = False,
    timeout: float = 240,
) -> Report:
    """Collector test: real agent expectations, a scripted Cortex XDR, the real XDR collector.

    The agent runs a marker command; the fake XDR (ofapi) answers with alerts naming that
    implant process; the palo-alto-cortex-xdr collector must match them and report the verdict
    to OpenAEV. verdict: prevented (detect + prevent), detected (detect only) or none.
    """
    alerts_actions, expected = XDR_VERDICTS[verdict]
    report = Report(f"cortex-xdr ({verdict})")
    collector = checkout("collectors", "palo-alto-cortex-xdr", collector_path)
    run_name = f"collector-{Path(collector).name}"
    fake = None
    try:
        fake = fakes.ofapi_up()
        fake.reset()
        report.refs["vendor_fake"] = fake.base
        made = ops.agent_expectations(profile, asset_id)
        report.refs["inject_id"] = made["inject_id"]
        report.refs["inject"] = made["link"]
        report.refs["endpoint"] = f"{made['endpoint']['name']} ({made['endpoint']['asset_id']})"
        report.check("agent executes the marker payload", made["status"] == "EXECUTED", made)
        implants = {
            s["value"]
            for e in made["pending"]
            for s in e["signatures"]
            if s["type"] == "parent_process_name"
        }
        report.evidence["pending_expectations"] = made["pending"]
        if not report.check("expectations carry the implant process", implants, made["pending"]):
            return report
        implant = sorted(implants)[0]
        # The collector looks for alerts up to the expectation end date: stamp them there
        ended = next(
            (
                s["value"]
                for e in made["pending"]
                for s in e["signatures"]
                if s["type"] == "end_date"
            ),
            None,
        )
        stamp = ops.parse_date(ended).timestamp() if ended else time.time()
        alerts = [
            _xdr_alert(i + 1, implant, action, int(stamp * 1000))
            for i, action in enumerate(alerts_actions)
        ]
        reply = {"total_count": len(alerts), "result_count": len(alerts), "alerts": alerts}
        fake.rule(XDR_ALERTS_PATH, [{"body": {"reply": reply}}])
        up = _start(
            report,
            profile,
            collector,
            "collector",
            kind="collector",
            env={
                "PALO_ALTO_CORTEX_XDR_FQDN": fake.url("palo-alto-cortex-xdr"),
                "PALO_ALTO_CORTEX_XDR_API_KEY": "staticfire-fake-key",
                "PALO_ALTO_CORTEX_XDR_API_KEY_ID": "1",
                "COLLECTOR_PERIOD": "PT15S",
                "REQUESTS_CA_BUNDLE": str(fake.cert),
            },
        )
        if not up:
            return report
        collector_id = up["component"]["id"]
        asset = made["endpoint"]["asset_id"]
        answered_types = tuple(t for t, result in expected.items() if result)
        if answered_types:
            done, expectations = ops.wait_expectations(
                profile, made["inject_id"], asset, collector_id, answered_types, timeout
            )
            report.check(f"collector answers {', '.join(answered_types)} in time", done)
        else:
            # Nothing to wait for: give the collector a few cycles to (wrongly) answer
            wait_until(lambda: False, 50, 5)
            expectations = ops.expectations_of_target(ops.client(profile), made["inject_id"], asset)
        report.evidence["expectations"] = expectations
        for kind, result in expected.items():
            mine = [
                r["result"]
                for e in expectations
                if e["type"] == kind
                for r in e["results"]
                # OpenAEV pre-creates an empty result slot per collector it expects an answer from
                if r["source_id"] == collector_id and r["result"]
            ]
            if result:
                report.check(f"{kind} answered '{result}' by the collector", mine == [result], mine)
            else:
                report.check(f"{kind} left unanswered by the collector", not mine, mine)
        calls = fake.journal(XDR_ALERTS_PATH)
        report.evidence["vendor_calls"] = calls[:3]
        report.check("collector queried the XDR alerts API", calls, "no call recorded")
    except Exception as err:
        report.error = f"{type(err).__name__}: {err}"
    finally:
        if report.verdict != "PASS":
            report.evidence["collector_log"] = _safe_tail(run_name)
        if not keep:
            runner.stop(run_name)
            if fake and fake.started:
                runner.stop(fakes.OFAPI_RUN)
    return report


def _safe_tail(run_name: str) -> str | None:
    try:
        return runner.tail(run_name, 40)
    except Exception:
        return None


RECIPES: dict[str, Callable[..., Report]] = {
    "email-smtp": email_smtp,
    "mailpit-collector": mailpit_collector,
    "cortex-xdr": cortex_xdr,
}

DESCRIPTIONS = {
    "email-smtp": "Injector test: craft an email through the email-smtp injector, check that "
    "mailpit received it with the right sender, recipients, subject, body and header.",
    "mailpit-collector": "Collector test: an email inject with DETECTION/PREVENTION expectations "
    "on an agent endpoint, answered by the mailpit collector (Detected / Not Prevented).",
    "cortex-xdr": "Collector test: the agent runs a marker command, a scripted Cortex XDR "
    "(ofapi) reports alerts on that implant, the palo-alto-cortex-xdr collector must answer "
    "OpenAEV. Option verdict: prevented (default), detected or none.",
}
