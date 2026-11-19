"""End-to-end recipes: fire a component at the real platform and check every observable effect.

Each recipe returns a Report (checks + verdict + refs + evidence). Recipes start the components
they need from their checkouts and stop them afterwards unless ``keep`` is set.
"""

from __future__ import annotations

import functools
import os
import time
import uuid
from collections.abc import Callable
from pathlib import Path

from staticfire import fakes, ops, runner, vendors
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


CARRIERS = ("header", "url", "attachment")


def _place_implants(api, content: dict, implants: list[str], carrier: str) -> list[dict]:
    """Write the implant names into the email carrier; returns the documents to attach."""
    if carrier == "header":
        content["custom_headers"] = f"X-OpenAEV-Implant: {', '.join(implants)}"
    elif carrier == "url":
        links = "\n".join(f"https://staticfire.test/landing?ref={i}" for i in implants)
        content["body"] = f"{content['body']}\n{links}"
    elif carrier == "attachment":
        document = api.upload_document(
            f"{implants[0]}.txt",
            ("staticfire attachment\n" + "\n".join(implants) + "\n").encode(),
            "Implant carrier uploaded by staticfire",
        )
        return [{"document_id": document["document_id"], "document_attached": True}]
    elif carrier != "none":
        raise ValueError(f"Unknown carrier {carrier}, known: {CARRIERS} or none")
    return []


def _carried(mail: dict, implants: list[str], carrier: str) -> bool:
    if carrier == "header":
        values = mail["custom_headers"].get("X-Openaev-Implant") or []
        return all(any(i in v for v in values) for i in implants)
    if carrier == "url":
        return all(f"ref={i}" in (mail["text"] or "") for i in implants)
    return any(a["file_name"] == f"{implants[0]}.txt" for a in mail["attachments"])


def _carried_anywhere(mail: dict, implants: list[str]) -> bool:
    texts = [mail["text"] or "", mail["html"] or ""]
    texts += [v for values in mail["custom_headers"].values() for v in values]
    texts += [a["file_name"] or "" for a in mail["attachments"]]
    return any(i in t for i in implants for t in texts)


def _fire_carrier(
    report: Report,
    profile: Profile,
    carrier: str,
    contract_id: str,
    injector_type: str,
    endpoint: dict,
    collector_id: str,
    timeout: float,
) -> None:
    api = ops.client(profile)
    token = uuid.uuid4().hex[:10]
    content = _email_content(profile, token)
    content["expectations"] = ops.expectation_content(ops.TECHNICAL_EXPECTATIONS)
    base = {
        "inject_title": f"staticfire mailpit-collector {carrier} {token}",
        "inject_injector_contract": contract_id,
        "inject_assets": [endpoint["asset_id"]],
    }
    inject_id = api.create_atomic_testing({**base, "inject_content": content})["inject_id"]
    # The name OpenAEV gives the inject's implant on each agent: its parent_process_name signature
    implants = [
        f"{injector_type}{inject_id}-agent-{a['agent_id']}"
        for a in endpoint["agents"]
        if a["active"]
    ]
    documents = _place_implants(api, content, implants, carrier)
    api.update_atomic_testing(
        inject_id, {**base, "inject_content": content, "inject_documents": documents}
    )
    result = ops.launch_and_wait(profile, inject_id, [endpoint["asset_id"]])
    report.refs[f"{carrier}_inject"] = result["link"]
    report.check(f"[{carrier}] inject EXECUTED", result["status"] == "EXECUTED", result["status"])
    box = ops.mailpit(profile)
    messages = box.wait_for(f'to:"{content["to"]}"', timeout=60)
    if not report.check(f"[{carrier}] email delivered", messages, f"nothing for {content['to']}"):
        return
    mail = box.describe(messages[0]["ID"])
    report.refs[f"{carrier}_message"] = f"{profile.mailpit_url}/view/{mail['id']}"
    if carrier == "none":
        # Negative case: no implant anywhere, the collector must leave the expectations pending
        report.check("[none] email carries no implant", not _carried_anywhere(mail, implants), mail)
        wait_until(lambda: False, 45, 5)  # several collector cycles
        expectations = ops.expectations_of_target(api, inject_id, endpoint["asset_id"])
        answers = [
            r
            for e in expectations
            for r in e["results"]
            if r["source_id"] == collector_id and r["result"]
        ]
        report.check("[none] collector leaves the expectations unanswered", not answers, answers)
        return
    report.check(f"[{carrier}] email carries the implant", _carried(mail, implants, carrier), mail)
    answered, expectations = ops.wait_expectations(
        profile, inject_id, endpoint["asset_id"], collector_id, timeout=timeout
    )
    report.evidence[f"{carrier}_expectations"] = expectations
    report.check(f"[{carrier}] collector answers every expectation in time", answered)
    for kind, expected in (("DETECTION", "Detected"), ("PREVENTION", "Not Prevented")):
        mine = [
            r
            for e in expectations
            if e["type"] == kind
            for r in e["results"]
            # OpenAEV pre-creates an empty result slot per collector it expects an answer from
            if r["source_id"] == collector_id and r["result"]
        ]
        report.check(
            f"[{carrier}] {kind} answered '{expected}', matched in the {carrier}",
            bool(mine)
            and mine[0]["result"] == expected
            and (mine[0]["metadata"] or {}).get("carrier") == carrier,
            mine,
        )


def mailpit_collector(
    profile: Profile,
    injector_path: str | None = None,
    collector_path: str | None = None,
    asset_id: str | None = None,
    carrier: str = "all",
    keep: bool = False,
    timeout: float = 180,
) -> Report:
    """Collector test: email injects carrying their implant name, answered by a collector.

    For each carrier (header, url, attachment, or all; none for the negative case: no implant,
    nothing must be answered), an email inject targets an agent
    endpoint with DETECTION/PREVENTION expectations; its implant name (the expectations'
    parent_process_name) is written in that carrier of the email. The collector under test
    (staticfire's mailpit collector by default) must find it and answer Detected / Not
    Prevented. email-smtp cannot place the implant itself yet: the recipe edits the inject.
    """
    carriers = CARRIERS if carrier == "all" else (carrier,)
    report = Report(f"mailpit-collector ({', '.join(carriers)})")
    injector = checkout("injectors", "email-smtp", injector_path)
    collector = collector_path or str(MAILPIT_COLLECTOR)
    runs = ["injector-email-smtp", f"collector-{Path(collector).name}"]
    try:
        endpoint = ops.agent_endpoint(profile, asset_id)
        report.refs["endpoint"] = f"{endpoint['name']} ({endpoint['asset_id']})"
        injector_up = _start(report, profile, injector, "injector")
        if not injector_up:
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
        for name in carriers:
            _fire_carrier(
                report,
                profile,
                name,
                injector_up["contracts"][0]["contract_id"],
                injector_up["entity"]["type"],
                endpoint,
                collector_up["component"]["id"],
                timeout,
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


def _signals(made: dict) -> vendors.Signals:
    """What the agent run left for a vendor to see, from its pending expectations."""
    signatures = {}
    for expectation in made["pending"]:
        for signature in expectation["signatures"]:
            signatures.setdefault(signature["type"], signature["value"])
    now = time.time()
    start = ops.parse_date(signatures["start_date"]) if "start_date" in signatures else None
    end = ops.parse_date(signatures["end_date"]) if "end_date" in signatures else None
    return vendors.Signals(
        inject_id=made["inject_id"],
        agent_id=made["pending"][0]["agent"],
        asset_id=made["endpoint"]["asset_id"],
        hostname=made["endpoint"]["name"],
        implant=signatures["parent_process_name"],
        start=start or ops.datetime.fromtimestamp(now - 60, ops.UTC),
        end=end or ops.datetime.fromtimestamp(now, ops.UTC),
        ips=made["pending"][0]["network_signatures"],
    )


def vendor_collector(
    profile: Profile,
    spec_name: str,
    verdict: str | None = None,
    collector_path: str | None = None,
    asset_id: str | None = None,
    keep: bool = False,
    timeout: float = 240,
) -> Report:
    """Collector test: real agent expectations, a scripted vendor (ofapi), the real collector.

    The agent runs a marker command; the fake vendor answers with data built from the
    expectations' signatures for the verdict (see vendors.SPECS); the collector must report that
    verdict to OpenAEV, leave the rest pending, and have queried its vendor.
    """
    spec = vendors.SPECS[spec_name]
    verdict = verdict or spec.verdicts[0]
    if verdict not in spec.expected:
        raise ValueError(f"{spec.recipe} supports verdicts {spec.verdicts}")
    expected = spec.expected[verdict]
    report = Report(f"{spec.recipe} ({verdict})")
    collector = checkout("collectors", spec.collector, collector_path)
    run_name = f"collector-{Path(collector).name}"
    fake = None
    try:
        fake = fakes.ofapi_up()
        fake.reset()
        report.refs["vendor_fake"] = f"{fake.http_base} / {fake.base}"
        made = ops.agent_expectations(profile, asset_id)
        report.refs["inject_id"] = made["inject_id"]
        report.refs["inject"] = made["link"]
        report.refs["endpoint"] = f"{made['endpoint']['name']} ({made['endpoint']['asset_id']})"
        report.check("agent executes the marker payload", made["status"] == "EXECUTED", made)
        report.evidence["pending_expectations"] = made["pending"]
        if not report.check(
            "expectations carry the implant process",
            any(
                s["type"] == "parent_process_name" for e in made["pending"] for s in e["signatures"]
            ),
            made["pending"],
        ):
            return report
        signals = _signals(made)
        report.evidence["signals"] = signals.__dict__ | {
            "start": signals.start_iso,
            "end": signals.end_iso,
        }
        for rule in spec.rules(signals, verdict):
            fake.rule(rule.path, [rule.response()], method=rule.method)
        up = _start(
            report,
            profile,
            collector,
            "collector",
            kind="collector",
            env={**spec.env(fake), "COLLECTOR_PERIOD": spec.period},
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
            wait_until(lambda: False, 60, 5)
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
        for path in spec.calls:
            calls = fake.journal(path)
            report.evidence.setdefault("vendor_calls", {})[path] = calls[:3]
            report.check(f"collector called {path}", calls, "no call recorded")
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
    **{name: functools.partial(vendor_collector, spec_name=name) for name in vendors.SPECS},
}

DESCRIPTIONS = {
    "email-smtp": "Injector test: craft an email through the email-smtp injector, check that "
    "mailpit received it with the right sender, recipients, subject, body and header.",
    "mailpit-collector": "Collector test: email injects with DETECTION/PREVENTION expectations "
    "on an agent endpoint, their implant name written in a header, a body URL or an attachment "
    "(option carrier: header, url, attachment, all, or none for the negative case); the mailpit "
    "collector must find it and answer Detected / Not Prevented.",
    **{
        name: f"Collector test: the agent runs a marker command, ofapi plays the vendor of "
        f"{spec.collector} ({spec.description}); the collector must answer OpenAEV. Option "
        f"verdict: {', '.join(spec.verdicts)}."
        for name, spec in vendors.SPECS.items()
    },
}
