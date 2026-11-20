"""End-to-end recipes: fire a component at the real platform and check every observable effect.

Each recipe returns a Report (checks + verdict + refs + evidence). Recipes start the components
they need from their checkouts and stop them afterwards unless ``keep`` is set.
"""

from __future__ import annotations

import functools
import inspect
import json
import os
import re
import shutil
import time
import uuid
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path

from staticfire import (
    ai_vendors,
    catalog_vendors,
    config,
    connector_vendors,
    fakes,
    injector_vendors,
    logscan,
    ops,
    runner,
    shims,
    vendors,
)
from staticfire.config import Profile
from staticfire.openaev import wait_until
from staticfire.opencti import OpenCTI
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
        # Collectors and injectors have a pyproject.toml, most OpenCTI connectors a src/ folder
        if (candidate / "pyproject.toml").exists() or (candidate / "src").is_dir():
            return str(candidate)
    raise FileNotFoundError(
        f"No {repo}/{name} checkout found (tried {[str(c) for c in candidates]}); pass its path"
    )


def _literal_prefix(path: str) -> str:
    """The literal start of a rule path (a regex when it starts with '^')."""
    if not path.startswith("^"):
        return path
    return re.split(r"[\\.^$*+?{}\[\]|()]", path[1:], maxsplit=1)[0]


def _reset_own(fake, paths) -> None:
    """Forget ofapi's rules and journal under this test's own paths only: concurrent tests
    (OpenCTI connectors) share the fake, a global reset would wipe their rules."""
    for prefix in sorted({_literal_prefix(p) for p in paths}):
        if prefix.strip("/"):
            fake.reset(prefix)


# ofapi prefixes several vendors' tests use (modules shared by every Microsoft, Google... fake)
SHARED_PREFIXES = {
    "/microsoft-graph",
    "/microsoft-login",
    "/microsoft-identity",
    "/google-identity",
    "/google-oauth2",
    "/github",
    "/aws",
}


def _root(path: str) -> str:
    return "/" + _literal_prefix(path).strip("/").split("/")[0]


def _install_rules(fake, rules) -> None:
    """Script the fake: each rule replaces any earlier one on its path."""
    _reset_own(fake, [rule.path for rule in rules])
    for rule in rules:
        fake.rule(rule.path, [rule.response()], method=rule.method)


def _clock_ok(report: Report, profile: Profile) -> bool:
    """Collectors judge expectations by age: refuse to run on a platform with a wrong clock."""
    problem = ops.clock_problem(profile)
    if problem:
        report.error = problem
    return problem is None


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
        if not _clock_ok(report, profile):
            return report
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
    edr_run = None
    fake = None
    try:
        if not _clock_ok(report, profile):
            return report
        fake = fakes.ofapi_up()
        _reset_own(fake, spec.calls)
        report.refs["vendor_fake"] = f"{fake.http_base} / {fake.base}"
        if spec.email:
            made = _email_expectations(report, profile, asset_id)
            if not made:
                return report
        else:
            made = ops.agent_expectations(profile, asset_id)
        report.refs["inject_id"] = made["inject_id"]
        report.refs["inject"] = made["link"]
        report.refs["endpoint"] = f"{made['endpoint']['name']} ({made['endpoint']['asset_id']})"
        what = "email inject EXECUTED" if spec.email else "agent executes the marker payload"
        report.check(what, made["status"] == "EXECUTED", made)
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
        signals.email = made.get("email") or {}
        report.evidence["signals"] = signals.__dict__ | {
            "start": signals.start_iso,
            "end": signals.end_iso,
        }
        if spec.edr:
            edr_dir = checkout("collectors", vendors.SPECS[spec.edr].collector)
            edr_run = f"collector-{Path(edr_dir).name}"
            if not _edr_first(report, profile, fake, spec.edr, verdict, made, signals, timeout):
                return report
        _install_rules(fake, spec.rules(signals, verdict))
        up = _start(
            report,
            profile,
            collector,
            "collector",
            kind="collector",
            env={
                **(fakes.component_proxy_env(fake, profile.host) if spec.proxy else {}),
                **spec.env(fake),
                "COLLECTOR_PERIOD": spec.period,
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
        if report.verdict != "PASS" and edr_run:
            report.evidence["edr_collector_log"] = _safe_tail(edr_run)
        if not keep:
            runner.stop(run_name)
            if edr_run:
                runner.stop(edr_run)
            if spec.email:
                runner.stop("injector-email-smtp")
            if fake and fake.started:
                runner.stop(fakes.OFAPI_RUN)
    return report


def _edr_first(
    report: Report,
    profile: Profile,
    fake,
    edr: str,
    verdict: str,
    made: dict,
    signals: vendors.Signals,
    timeout: float,
) -> bool:
    """Run the EDR collector a SIEM chains on (its own spec, same verdict) until it answered
    what that verdict implies; record the alertIds it left in its results."""
    spec = vendors.SPECS[edr]
    signals.edr = edr
    _reset_own(fake, spec.calls)
    _install_rules(fake, spec.rules(signals, verdict))
    up = _start(
        report,
        profile,
        checkout("collectors", spec.collector),
        f"edr_{edr}",
        kind="collector",
        env={
            **(fakes.component_proxy_env(fake, profile.host) if spec.proxy else {}),
            **spec.env(fake),
            "COLLECTOR_PERIOD": spec.period,
        },
    )
    if not up:
        return False
    edr_id = up["component"]["id"]
    asset = made["endpoint"]["asset_id"]
    answered = tuple(t for t, r in spec.expected[verdict].items() if r)
    if answered:
        done, expectations = ops.wait_expectations(
            profile, made["inject_id"], asset, edr_id, answered, timeout
        )
        report.check(f"{edr} answers {', '.join(answered)} first", done)
    else:
        wait_until(lambda: False, 30, 5)
        expectations = ops.expectations_of_target(ops.client(profile), made["inject_id"], asset)
    results = [
        r for e in expectations for r in e["results"] if r["source_id"] == edr_id and r["result"]
    ]
    report.evidence["edr_results"] = results
    signals.edr_alert_ids = sorted(
        {str((r.get("metadata") or {}).get("alertId")) for r in results} - {"None"}
    )
    return True


def _email_expectations(report: Report, profile: Profile, asset_id: str | None) -> dict | None:
    """Email expectations for an email security collector: email-smtp delivers an inject
    targeting the agent endpoint, its implant name in a body URL (email-smtp cannot place it:
    the inject is edited, see mailpit_collector). Shaped like ops.agent_expectations, plus the
    delivered message."""
    endpoint = ops.agent_endpoint(profile, asset_id)
    up = _start(report, profile, checkout("injectors", "email-smtp"), "injector")
    if not up:
        return None
    api = ops.client(profile)
    token = uuid.uuid4().hex[:10]
    content = _email_content(profile, token)
    content["expectations"] = ops.expectation_content(ops.TECHNICAL_EXPECTATIONS)
    base = {
        "inject_title": f"staticfire email expectations {token}",
        "inject_injector_contract": up["contracts"][0]["contract_id"],
        "inject_assets": [endpoint["asset_id"]],
    }
    inject_id = api.create_atomic_testing({**base, "inject_content": content})["inject_id"]
    implants = [
        f"{up['entity']['type']}{inject_id}-agent-{a['agent_id']}"
        for a in endpoint["agents"]
        if a["active"]
    ]
    _place_implants(api, content, implants, "url")
    api.update_atomic_testing(inject_id, {**base, "inject_content": content})
    result = ops.launch_and_wait(profile, inject_id, [endpoint["asset_id"]])
    box = ops.mailpit(profile)
    messages = box.wait_for(f'to:"{content["to"]}"', timeout=60)
    if not report.check("email delivered to mailpit", messages, f"nothing for {content['to']}"):
        return None
    mail = box.describe(messages[0]["ID"])
    report.refs["mailpit_message"] = f"{profile.mailpit_url}/view/{mail['id']}"
    urls = re.findall(r"https?://\S+", mail["text"] or "")
    return {
        **result,
        "inject_id": inject_id,
        "endpoint": endpoint,
        "pending": ops.pending_expectations(profile, inject_id),
        "email": {
            "from": content["from"],
            "to": content["to"],
            "cc": content["cc"],
            "subject": content["subject"],
            "urls": urls,
            "message_id": mail.get("message_id") or f"<{token}@staticfire.test>",
            "date": mail.get("date"),
        },
    }


def vendor_injector(
    profile: Profile,
    spec_name: str,
    injector_path: str | None = None,
    pyoaev: str | None = None,
    keep: bool = False,
    timeout: float = 180,
) -> Report:
    """Injector test: fire an injector at a fake vendor or a stubbed tool (see injector_vendors).

    Checks the inject status, the injector's completion message, the findings the platform
    created from its outputs and the calls the fake received.
    """
    spec = injector_vendors.SPECS[spec_name]
    report = Report(spec.recipe)
    injector = checkout("injectors", spec.injector, injector_path)
    run_name = f"injector-{Path(injector).name}"
    fake = None
    try:
        fake = fakes.ofapi_up()
        _reset_own(fake, [path for _, path in spec.calls])
        stub_dir = injector_vendors.write_stubs(spec)
        endpoint = ops.agent_endpoint(profile) if spec.target_endpoint else None
        ctx = injector_vendors.Context(fake, uuid.uuid4().hex[:10], stub_dir, endpoint)
        _install_rules(fake, spec.rules(ctx))
        env = {
            **(fakes.component_proxy_env(fake, profile.host) if spec.proxy else {}),
            **spec.env(ctx),
        }
        if any(name != "sitecustomize.py" for name in spec.stubs):
            env.setdefault("PATH", f"{stub_dir}:{os.environ.get('PATH', '')}")
        up = _start(report, profile, injector, "injector", env=env, pyoaev=pyoaev)
        if not up:
            return report
        contract_ids = [c["contract_id"] for c in up["contracts"]]
        if not report.check(f"contract {spec.contract} registered", spec.contract in contract_ids):
            return report
        assets = [endpoint["asset_id"]] if endpoint else []
        result = ops.run_inject(
            profile,
            spec.contract,
            spec.content(ctx),
            assets=assets,
            expectations=spec.expectations or None,
            title=f"staticfire {spec.recipe} {ctx.token}",
            timeout=timeout,
        )
        report.refs["inject_id"] = result["inject_id"]
        report.refs["inject"] = result["link"]
        report.evidence["traces"] = result["traces"]
        report.check(
            f"inject status {spec.status}", result["status"] == spec.status, result["status"]
        )
        complete = [t["message"] or "" for t in result["traces"] if t["action"] == "COMPLETE"]
        if spec.message:
            report.check(
                f"completion message matches {spec.message!r}",
                any(re.search(spec.message, m) for m in complete),
                complete,
            )
        if spec.findings:
            findings = ops.inject_findings(profile, result["inject_id"])
            report.evidence["findings"] = findings
            for kind, value in spec.findings:
                report.check(
                    f"finding {kind} containing {value!r}",
                    any(f["type"] == kind and value in (f["value"] or "") for f in findings),
                    [f"{f['type']}: {f['value']}" for f in findings][:20],
                )
        for method, path in spec.calls:
            calls = [c for c in fake.journal(path) if c.get("method") == method]
            report.evidence.setdefault("vendor_calls", {})[path] = calls[:2]
            report.check(f"injector called {method} {path}", calls, "no call recorded")
    except Exception as err:
        report.error = f"{type(err).__name__}: {err}"
    finally:
        if report.verdict != "PASS":
            report.evidence["injector_log"] = _safe_tail(run_name)
        if not keep:
            runner.stop(run_name)
            if fake and fake.started:
                runner.stop(fakes.OFAPI_RUN)
    return report


def catalog_collector(
    profile: Profile,
    spec_name: str,
    collector_path: str | None = None,
    keep: bool = False,
    timeout: float | None = None,
) -> Report:
    """Catalog/asset collector test: import a fake dataset, check what the platform holds."""
    spec = catalog_vendors.SPECS[spec_name]
    report = Report(spec.recipe)
    collector = checkout("collectors", spec.collector, collector_path)
    run_name = f"collector-{Path(collector).name}"
    fake = None
    try:
        if not _clock_ok(report, profile):
            return report
        fake = fakes.ofapi_up()
        _reset_own(fake, spec.calls)
        if spec.setup:
            spec.setup(ops.client(profile), fake)
        env = {
            **(fakes.component_proxy_env(fake, profile.host) if spec.proxy else {}),
            **spec.env(fake),
        }
        up = _start(report, profile, collector, "collector", kind="collector", env=env)
        if not up:
            return report
        collector_id = up["component"]["id"]
        api = ops.client(profile)
        last: list = []
        # Calls are kept once seen: the shared journal rotates under concurrent tests
        seen: dict[str, list] = {}

        def settled() -> bool:
            nonlocal last
            for path in spec.calls:
                seen[path] = seen.get(path) or fake.journal(path)[:2]
            # Data left by an earlier run would pass at once: wait for this run's fetch too
            if not all(seen.values()):
                return False
            last = spec.checks(api, collector_id)
            return all(ok for _, ok, _ in last)

        wait_until(settled, timeout or spec.timeout, 10)
        last = last or spec.checks(api, collector_id)
        for name, ok, detail in last:
            report.check(name, ok, detail)
        for path in spec.calls:
            calls = seen.get(path) or fake.journal(path)
            report.evidence.setdefault("source_calls", {})[path] = calls[:2]
            report.check(f"collector fetched {path}", calls, "no call recorded")
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


AI_TARGET_NAME = "staticfire AI target (ofapi)"


def _ai_target(profile: Profile, fake) -> str:
    """The AI target pointing at the fake OpenAI-compatible model, created once."""
    api = ops.client(profile)
    found = api.post(
        "/api/ai_targets/search", {"page": 0, "size": 20, "textSearch": AI_TARGET_NAME}
    )
    for target in (found or {}).get("content", []):
        if target.get("asset_name") == AI_TARGET_NAME:
            return target["asset_id"]
    created = api.post(
        "/api/ai_targets",
        {
            "asset_name": AI_TARGET_NAME,
            "ai_target_provider": "OPENAI_COMPATIBLE",
            "ai_target_endpoint": fake.http_url("openai/v1"),
            "ai_target_model": "gpt-4o-mini",
            "ai_target_modality": "TEXT",
            "ai_target_token": "staticfire-fake-token",
        },
    )
    return created["asset_id"]


def ai_collector(
    profile: Profile,
    spec_name: str,
    verdict: str | None = None,
    injector_path: str | None = None,
    collector_path: str | None = None,
    keep: bool = False,
    timeout: float = 240,
) -> Report:
    """AI defense test: ai-redteam attacks a fake model, an AI firewall collector judges it."""
    spec = ai_vendors.SPECS[spec_name]
    verdict = verdict or spec.verdicts[0]
    if verdict not in spec.expected:
        raise ValueError(f"{spec.recipe} supports verdicts {spec.verdicts}")
    expected = spec.expected[verdict]
    report = Report(f"{spec.recipe} ({verdict})")
    injector = checkout("injectors", "ai-redteam", injector_path)
    collector = checkout("collectors", spec.collector, collector_path)
    runs = ["injector-ai-redteam", f"collector-{Path(collector).name}"]
    fake = None
    try:
        if not _clock_ok(report, profile):
            return report
        fake = fakes.ofapi_up()
        _reset_own(fake, [*spec.calls, "/openai/v1/chat/completions"])
        if not _start(report, profile, injector, "injector"):
            return report
        # The collector registers its security platform: it must exist before the launch
        up = _start(
            report,
            profile,
            collector,
            "collector",
            kind="collector",
            env={
                **(fakes.component_proxy_env(fake, profile.host) if spec.proxy else {}),
                **spec.env(fake),
                "COLLECTOR_PLATFORM": spec.platform,
                "COLLECTOR_PERIOD": "PT10S",
            },
        )
        if not up:
            return report
        collector_id = up["component"]["id"]
        target = _ai_target(profile, fake)
        report.refs["ai_target"] = target
        expectations = [
            {
                **e,
                "expectation_expected_security_platform_types": ai_vendors.FIREWALL_PLATFORMS,
            }
            for e in ops.expectation_content(ops.TECHNICAL_EXPECTATIONS)
        ]
        created = ops.run_inject(
            profile,
            ai_vendors.AI_REDTEAM_DIRECT_INJECTION,
            {
                "target_selector": "ai_target",
                "ai_target": target,
                "attack_prompt": ai_vendors.ATTACK_PROMPT,
                "converters": "none",
                "expectations": expectations,
            },
            title=f"staticfire {spec.recipe} {verdict}",
            launch=False,
        )
        inject_id = created["inject_id"]
        _install_rules(fake, spec.rules(inject_id, verdict))
        result = ops.launch_and_wait(profile, inject_id, timeout=timeout)
        report.refs["inject_id"] = inject_id
        report.refs["inject"] = result["link"]
        report.evidence["traces"] = result["traces"]
        report.check("inject status EXECUTED", result["status"] == "EXECUTED", result["status"])
        complete = [t["message"] or "" for t in result["traces"] if t["action"] == "COMPLETE"]
        report.check(
            "model refused the attack (DEFENDED)", any("DEFENDED" in m for m in complete), complete
        )
        model_calls = fake.journal("/openai/v1/chat/completions")
        report.check("ai-redteam attacked the fake model", model_calls, "no call recorded")
        answered_types = tuple(t for t, r in expected.items() if r)
        if answered_types:
            done, results = ops.wait_expectations(
                profile, inject_id, target, collector_id, answered_types, timeout
            )
            report.check(f"collector answers {', '.join(answered_types)} in time", done)
        else:
            wait_until(lambda: False, 45, 5)
            results = ops.expectations_of_target(ops.client(profile), inject_id, target)
        report.evidence["expectations"] = results
        for kind, wanted in expected.items():
            mine = [
                r["result"]
                for e in results
                if e["type"] == kind
                for r in e["results"]
                if r["source_id"] == collector_id and r["result"]
            ]
            if wanted:
                report.check(f"{kind} answered '{wanted}' by the collector", mine == [wanted], mine)
            else:
                report.check(f"{kind} left unanswered by the collector", not mine, mine)
        for path in spec.calls:
            calls = fake.journal(path)
            report.evidence.setdefault("vendor_calls", {})[path] = calls[:2]
            report.check(f"collector called {path}", calls, "no call recorded")
    except Exception as err:
        report.error = f"{type(err).__name__}: {err}"
    finally:
        if report.verdict != "PASS":
            report.evidence["logs"] = {name: _safe_tail(name) for name in runs}
        if not keep:
            for name in runs:
                runner.stop(name)
            if fake and fake.started:
                runner.stop(fakes.OFAPI_RUN)
    return report


def _cti_profile(profile: Profile) -> Profile:
    """The profile itself if it holds OpenCTI, otherwise the first saved one that does."""
    if profile.opencti_url:
        return profile
    for name in config.list_profiles():
        candidate = config.load_profile(name)
        if candidate.opencti_url:
            return candidate
    raise ValueError("No profile with an OpenCTI platform: staticfire profile from-multipass <vm>")


def _connector_works(cti, connector_id: str, since: float) -> list[dict]:
    connector = cti.connector(connector_id) or {}
    works = [
        w
        for w in connector.get("works") or []
        if ops.parse_date(w["timestamp"]).timestamp() >= since - 5
    ]
    return works


# A connector run is over when its works are complete and it sent nothing for this long
QUIET_SECONDS = 30


def _service_token(profile: Profile, cti, name: str) -> tuple[str, str]:
    """(user id, token) of the connector's own service account, reusing a stored token."""
    store = config.STATE_DIR / "opencti-users.json"
    tokens = json.loads(store.read_text()) if store.exists() else {}
    key = f"{profile.opencti_url}|{name}"
    if known := tokens.get(key):
        try:
            if OpenCTI(profile.opencti_url, known["token"]).graphql("{ me { id } }")["me"]:
                return known["id"], known["token"]
        except Exception:
            pass
    user_id, token = cti.service_user(name)
    tokens[key] = {"id": user_id, "token": token}
    store.parent.mkdir(parents=True, exist_ok=True)
    store.write_text(json.dumps(tokens, indent=2))
    store.chmod(0o600)
    return user_id, token


def _enrichment_target(cti, enrich) -> str:
    if callable(enrich):
        return enrich(cti)
    kind, value = enrich
    if kind == "StixFile":
        return cti.create_file_observable(value)["id"]
    return cti.create_observable(kind, value)["id"]


def connector_test(
    profile: Profile,
    spec_name: str,
    connector_path: str | None = None,
    keep: bool = False,
    timeout: float | None = None,
) -> Report:
    """OpenCTI connector test: run it against ofapi (through the proxy), drive it as its family
    needs, judge its works and what its service account created."""
    spec = connector_vendors.SPECS[spec_name]
    report = Report(spec.recipe)
    if spec.blocked:
        report.skipped = spec.blocked
        return report
    connector_dir = Path(connector_path or checkout("connectors", spec.connector))
    run_name = f"connector-{connector_dir.name}"
    try:
        profile = _cti_profile(profile)
        cti = ops.cti_client(profile)
        report.refs["opencti"] = profile.opencti_url
        # ofapi and the proxy are shared by concurrent tests: started once, never stopped here
        fake = fakes.ofapi_up()
        report.refs["ofapi_reloaded"] = fake.reload()
        roots = {"/" + c.strip("/").split("/")[0] for c in spec.calls}
        # A vendor's own prefix is reset whole; one shared by several vendors (Graph, GitHub,
        # AWS...) only on this test's paths, or it would wipe a concurrent test's rules
        for prefix in roots - SHARED_PREFIXES:
            fake.reset(prefix)
        rules = spec.rules(fake)
        _reset_own(fake, [c for c in spec.calls if _root(c) in SHARED_PREFIXES])
        _install_rules(fake, rules)
        user_id, token = _service_token(profile, cti, f"staticfire-{spec.recipe}")
        env = {
            "OPENCTI_TOKEN": token,
            # one name per connector: its specs share its id, a rename would confuse OpenCTI
            "CONNECTOR_NAME": f"staticfire {connector_dir.name}",
            "CONNECTOR_DURATION_PERIOD": "PT1H",
            "CONNECTOR_RUN_AND_TERMINATE": "false",
            # from the spec: a copy of the connector (--connector-path) is not in a family folder
            "CONNECTOR_TYPE": runner.CONNECTOR_FAMILIES[spec.family],
            # the setting production should use (pycti warns about its default)
            "OPENCTI_TLS_REJECT_UNAUTHORIZED": "true",
        }
        if spec.family == "internal-enrichment":
            env["CONNECTOR_AUTO"] = "false"
        if spec.family == "stream":
            if spec.stream_filters:
                stream_id = cti.live_stream(f"staticfire-{spec.recipe}", spec.stream_filters)
            elif spec.stream is None:
                # only the test's own objects: the whole platform's changes flood a connector
                # opening a connection per event (and other tests' objects are not its concern)
                stream_id = cti.live_stream(STREAM_LABEL, _labelled(cti.label(STREAM_LABEL)))
            else:
                stream_id = cti.live_stream()
            env["CONNECTOR_LIVE_STREAM_ID"] = stream_id
            env["CONNECTOR_LIVE_STREAM_LISTEN_DELETE"] = "true"
            env["CONNECTOR_LIVE_STREAM_NO_DEPENDENCIES"] = "true"
        # pycti also writes every bundle it sends here: what the connector produced
        bundles_dir = runner.RUNS_DIR / run_name / "bundles"
        shutil.rmtree(bundles_dir, ignore_errors=True)
        bundles_dir.mkdir(parents=True)
        env["CONNECTOR_SEND_TO_DIRECTORY"] = "true"
        env["CONNECTOR_SEND_TO_DIRECTORY_PATH"] = str(bundles_dir)
        proxy = fakes.proxy_up(fake)
        # Without the proxy (clients ignoring it), the vendor URL points at ofapi itself
        env.update(proxy.env([profile.host or ""]) if spec.proxy else proxy.trust_env())
        env.update(spec.env(fake))
        env.update(shims.env(env.get("PYTHONPATH")))
        compose = connector_vendors.compose_defaults(connector_dir)
        env = {
            # a placeholder only where neither the compose file nor the spec gives a value
            **connector_vendors.schema_placeholders(connector_dir, {**compose, **env}),
            **compose,
            **env,
        }
        # a spec giving None leaves the variable out (a setting the connector refuses)
        env = {name: value for name, value in env.items() if value is not None}
        if spec.prepare:
            spec.prepare(cti)
        # Every run starts from a blank state (two specs of one connector share its id)
        cti.reset_state(runner.detect(str(connector_dir), "connector").component_id)
        started = time.time()
        # Works and objects carry the platform's time: a VM's clock drifts
        skew = logscan.host_skew(profile)
        report.refs["clock_skew_s"] = round(skew, 1)
        platform_started = started + skew
        up = _start(report, profile, str(connector_dir), "connector", kind="connector", env=env)
        if not up:
            return report
        connector_id = up["component"]["id"]
        if spec.family == "stream":
            _stream_checks(report, cti, fake, spec, timeout)
            _verify(report, cti, spec)
            return report
        if spec.family == "internal-enrichment" and spec.enrich:
            target = _enrichment_target(cti, spec.enrich)
            report.refs["enriched"] = target
            cti.ask_enrichment(target, connector_id)
        elif spec.family == "internal-import-file" and spec.import_file:
            file_name, source, mime = spec.import_file
            content = fake.http.get(source).raise_for_status().content
            uploaded = cti.upload_import(file_name, content, mime)
            report.refs["imported_file"] = uploaded["id"]
            cti.ask_import(uploaded["id"], connector_id)
        elif spec.family == "internal-export-file" and spec.export:
            mime, scope = spec.export
            object_id, entity_type = (spec.export_object or _default_export_object)(cti)
            report.refs["exported"] = object_id
            if scope == "entity":
                cti.ask_entity_export(object_id, mime)
            else:
                cti.ask_export([object_id], mime, entity_type)

        settled = {"bundles": -1, "since": time.time()}

        def done() -> list[dict] | None:
            """Every work complete, and no new bundle for a while: a run sending one bundle per
            page looks complete between two pages."""
            works = _connector_works(cti, connector_id, platform_started)
            bundles = len(list(bundles_dir.glob("*.json")))
            if bundles != settled["bundles"]:
                settled.update(bundles=bundles, since=time.time())
            if not works or any(w["status"] != "complete" for w in works):
                return None
            return works if time.time() - settled["since"] >= QUIET_SECONDS else None

        if not spec.opens_work:
            _knowledge_checks(report, cti, spec, user_id, platform_started, bundles_dir, timeout)
            _vendor_call_checks(report, fake, spec)
            _verify(report, cti, spec)
            return report
        finished, works = wait_until(done, timeout or spec.timeout, 10)
        works = works or _connector_works(cti, connector_id, platform_started)
        report.evidence["works"] = works
        if not report.check("a connector run (work) completes", finished, works):
            return report
        errors = [e for w in works for e in w.get("errors") or []]
        report.check("its works report no error", not errors, errors[:5])
        if spec.family in ("external-import", "internal-import-file"):
            processed = sum(w.get("completed_number") or 0 for w in works)
            report.check(
                f"its works processed at least {spec.min_elements} element(s)",
                processed >= spec.min_elements,
                processed,
            )
        since = datetime.fromtimestamp(platform_started - 5, UTC).strftime("%Y-%m-%dT%H:%M:%S.000Z")
        changed = cti.changed_since(since, creator_id=user_id)
        ingested = sorted({c.get("relationship_type") or c.get("entity_type") for c in changed})
        report.evidence["ingested_types"] = ingested
        sent = _sent_types(bundles_dir)
        report.evidence["sent_types"] = sent
        if spec.expected_types:
            report.check(
                f"it sent {sorted(spec.expected_types)}",
                spec.expected_types <= set(sent),
                sent,
            )
        if spec.family == "internal-export-file" and spec.export:
            files = cti.export_files(entity_type, object_id if scope == "entity" else None)
            mine = [f for f in files if f"(staticfire {connector_dir.name})" in f["name"]]
            report.evidence["export_files"] = mine[:3]
            report.check(
                "it produced a non-empty export file",
                any((f.get("size") or 0) > 0 for f in mine),
                [f["name"] for f in files][:5],
            )
        _vendor_call_checks(report, fake, spec)
        _verify(report, cti, spec)
    except Exception as err:
        report.error = f"{type(err).__name__}: {err}"
    finally:
        if report.verdict != "PASS":
            report.evidence["connector_log"] = _safe_tail(run_name)
        if not keep:
            runner.stop(run_name)
    return report


def _stix_types(changed: list[dict]) -> set[str]:
    """OpenCTI entity types as STIX ones ("relationship:<type>" for relationships)."""
    special = {"StixFile": "file", "stix-sighting-relationship": "sighting"}
    types = set()
    for item in changed:
        if item.get("relationship_type"):
            types |= {"relationship", f"relationship:{item['relationship_type']}"}
        elif item.get("entity_type"):
            types.add(special.get(item["entity_type"], item["entity_type"].lower()))
    return types


def _knowledge_checks(report, cti, spec, user_id, platform_started, bundles_dir, timeout) -> None:
    """For a connector writing through the API without opening works: what its own account
    created or updated, once nothing changed for a while."""
    since = datetime.fromtimestamp(platform_started - 5, UTC).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    settled = {"count": -1, "since": time.time()}

    def quiet() -> list[dict] | None:
        changed = cti.changed_since(since, creator_id=user_id)
        if len(changed) != settled["count"]:
            settled.update(count=len(changed), since=time.time())
        return changed if changed and time.time() - settled["since"] >= QUIET_SECONDS else None

    _, changed = wait_until(quiet, timeout or spec.timeout, 10)
    changed = changed or []
    types = _stix_types(changed) | set(_sent_types(bundles_dir))
    report.evidence["ingested_types"] = sorted(types)
    report.check(
        f"its account created at least {spec.min_elements} element(s) (it opens no work)",
        len(changed) >= spec.min_elements,
        len(changed),
    )
    if spec.expected_types:
        report.check(
            f"it created {sorted(spec.expected_types)}",
            spec.expected_types <= types,
            sorted(types),
        )


def _sent_types(bundles_dir: Path) -> list[str]:
    """STIX types of the bundles the connector sent ("relationship:<type>" for relationships)."""
    types = set()
    for path in bundles_dir.glob("*.json"):
        try:
            message = json.loads(path.read_text())
            # pycti wraps the bundle with its sending metadata
            objects = message.get("bundle", message).get("objects", [])
        except ValueError:
            continue
        for obj in objects:
            types.add(obj.get("type"))
            if obj.get("type") == "relationship":
                types.add(f"relationship:{obj.get('relationship_type')}")
    return sorted(filter(None, types))


def _verify(report: Report, cti, spec) -> None:
    for name, ok, detail in spec.verify(cti) if spec.verify else []:
        report.check(name, ok, detail)


def _journal_since(fake, path: str, since: float) -> list[dict]:
    """ofapi's journal under ``path`` since a time: concurrent tests share the fake."""
    return [e for e in fake.journal(path) if ops.parse_date(e["at"]).timestamp() >= since - 1]


def _vendor_call_checks(report: Report, fake, spec) -> None:
    for path in spec.calls:
        calls = _journal_since(fake, path, report.started_at)
        report.evidence.setdefault("vendor_calls", {})[path] = calls[:2]
        report.check(f"connector called {path}", calls, None if calls else "no call recorded")
    unrouted = {e["path"].split("/")[2] for e in fake.journal("/_unrouted/")}
    if unrouted:
        # Shared by concurrent tests: a hint, not a verdict
        report.evidence["unrouted_hosts"] = sorted(unrouted)


def _stream_checks(report: Report, cti, fake, spec, timeout: float | None) -> None:
    """A stream connector must forward what is created once it listens to its vendor: the
    unique values of the created objects must show in what the vendor received."""
    time.sleep(15)  # let it connect to the stream
    markers = (spec.stream or _default_stream_objects)(cti)
    report.refs["markers"] = markers

    def forwarded() -> list[dict] | None:
        calls = [e for path in spec.calls for e in _journal_since(fake, path, report.started_at)]
        return [e for e in calls if any(m in json.dumps(e) for m in markers)] or None

    _, found = wait_until(forwarded, timeout or spec.timeout, 5)
    _vendor_call_checks(report, fake, spec)
    if not spec.calls:
        report.check("the spec names the vendor calls to expect", False, "calls is empty")
        return
    report.evidence["forwarded"] = (found or [])[:2]
    report.check(f"the vendor received the new objects ({', '.join(markers)})", found, None)


# The label of the objects stream tests create, and the name of the live stream keeping only them
STREAM_LABEL = "staticfire-stream"


def _labelled(label_id: str) -> dict:
    return {
        "mode": "and",
        "filters": [{"key": ["objectLabel"], "values": [label_id], "operator": "eq"}],
        "filterGroups": [],
    }


def _default_stream_objects(cti) -> list[str]:
    """An indicator on a new domain and a new IPv4 observable; their values as markers."""
    token = uuid.uuid4().hex[:8]
    domain = f"sf-{token}.example.com"
    ip = f"198.51.{int(token[:2], 16) % 256}.{int(token[2:4], 16) % 254 + 1}"
    labels = [cti.label(STREAM_LABEL)]
    cti.create_indicator(
        f"staticfire {domain}", f"[domain-name:value = '{domain}']", "Domain-Name", labels=labels
    )
    cti.create_observable("IPv4-Addr", ip, labels=labels)
    return [domain, ip]


def _default_export_object(cti) -> tuple[str, str]:
    indicator = cti.create_indicator(
        f"staticfire export {uuid.uuid4().hex[:8]}",
        "[ipv4-addr:value = '198.51.100.7']",
        "IPv4-Addr",
    )
    return indicator["id"], "Indicator"


def _safe_tail(run_name: str) -> str | None:
    try:
        return runner.tail(run_name, 40)
    except Exception:
        return None


RECIPES: dict[str, Callable[..., Report]] = {
    "email-smtp": email_smtp,
    "mailpit-collector": mailpit_collector,
    **{name: functools.partial(vendor_collector, spec_name=name) for name in vendors.SPECS},
    **{name: functools.partial(vendor_injector, spec_name=name) for name in injector_vendors.SPECS},
    **{
        name: functools.partial(catalog_collector, spec_name=name) for name in catalog_vendors.SPECS
    },
    **{name: functools.partial(ai_collector, spec_name=name) for name in ai_vendors.SPECS},
    **{name: functools.partial(connector_test, spec_name=name) for name in connector_vendors.SPECS},
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
    **{
        name: f"Injector test: {spec.injector} ({spec.description})."
        for name, spec in injector_vendors.SPECS.items()
    },
    **{
        name: f"Collector test: {spec.collector} imports ofapi's dataset ({spec.description}); "
        "the platform must hold what it implies and nothing it excludes."
        for name, spec in catalog_vendors.SPECS.items()
    },
    **{
        name: f"AI defense test: ai-redteam attacks ofapi's model, {spec.collector} judges it "
        f"({spec.description}). Option verdict: {', '.join(spec.verdicts)}."
        for name, spec in ai_vendors.SPECS.items()
    },
    **{
        name: f"OpenCTI connector test: {spec.connector} against ofapi ({spec.description})."
        for name, spec in connector_vendors.SPECS.items()
    },
}


def verdicts_of(name: str) -> list[str | None]:
    """The verdicts a recipe can be run with ([None] when it takes none)."""
    if name in vendors.SPECS:
        return vendors.SPECS[name].verdicts
    if name in ai_vendors.SPECS:
        return ai_vendors.SPECS[name].verdicts
    return [None]


def run_recipe(profile: Profile, name: str, **options) -> Report:
    """Run a recipe, then review the warnings and errors logged meanwhile (components, platform)."""
    started_at = time.time()
    platform = "opencti" if name in connector_vendors.SPECS else "openaev"
    log_profile = profile
    try:
        if platform == "opencti":
            log_profile = _cti_profile(profile)
            skew = logscan.host_skew(log_profile)
        else:
            skew = ops.client(profile).clock_skew()
    except Exception:
        skew = 0.0
    fn = RECIPES[name]
    accepted = inspect.signature(fn).parameters
    report = fn(profile, **{k: v for k, v in options.items() if k in accepted and v})
    try:
        # Connector recipes may run concurrently: only their own run's component log is theirs
        # and OpenAEV recipes run beside them: leave the connectors' logs out of their review,
        # and the fakes' (one shared log, never rotated, of every vendor module)
        own = (
            [f"connector-{Path(connector_vendors.SPECS[name].connector).name}"]
            if (platform == "opencti")
            else [
                d.name
                for d in (runner.RUNS_DIR.iterdir() if runner.RUNS_DIR.exists() else [])
                if not d.name.startswith(("connector-", "fake-"))
            ]
        )
        logs = logscan.review(log_profile, started_at, skew, platform, runs=own)
        report.evidence["logs"] = logs
        report.refs["logs"] = logscan.one_line(logs)
        if platform == "opencti" and not report.skipped:
            # Connectors often catch their own failures and still complete their work
            errors = [
                entry["message"]
                for review in logs["components"].values()
                for entry in review["distinct"]
                if entry["level"] in ("ERROR", "CRITICAL", "FATAL")
            ]
            report.check("the connector logged no error", not errors, errors[:5])
    except Exception as err:  # the review must never hide the recipe's own verdict
        report.refs["logs"] = f"not reviewed: {err}"
    return report


def matrix(
    profile: Profile,
    names: list[str] | None = None,
    all_verdicts: bool = False,
    out_dir: Path | None = None,
    progress: Callable[[dict], None] | None = None,
    jobs: int = 1,
) -> list[dict]:
    """Run recipes and summarise them. OpenAEV recipes share the platform and the fake, so they
    run one after the other; connector recipes are independent and run ``jobs`` at a time."""
    from concurrent.futures import ThreadPoolExecutor

    def one(name: str, verdict: str | None) -> dict:
        report = run_recipe(profile, name, verdict=verdict)
        row = {
            "recipe": name,
            "verdict": verdict or "",
            "result": report.verdict,
            "duration_s": report.to_dict()["duration_s"],
            "failed": [c.name for c in report.checks if not c.ok],
            "error": report.error or report.skipped,
            "logs": report.refs.get("logs", ""),
        }
        if out_dir:
            out_dir.mkdir(parents=True, exist_ok=True)
            target = out_dir / f"{name}{'-' + verdict if verdict else ''}.json"
            target.write_text(json.dumps(report.to_dict(), indent=2, default=str))
            row["report"] = str(target)
        if progress:
            progress(row)
        return row

    runs = [
        (name, verdict)
        for name in names or list(RECIPES)
        for verdict in (verdicts_of(name) if all_verdicts else [None])
    ]
    serial = [run for run in runs if run[0] not in connector_vendors.SPECS]
    parallel = [run for run in runs if run[0] in connector_vendors.SPECS]
    rows = [one(*run) for run in serial]
    # Specs of one connector share its run: they go one after the other
    by_connector: dict[str, list] = {}
    for run in parallel:
        by_connector.setdefault(connector_vendors.SPECS[run[0]].connector, []).append(run)
    with ThreadPoolExecutor(max_workers=max(1, jobs)) as pool:
        groups = pool.map(lambda group: [one(*run) for run in group], by_connector.values())
        rows += [row for group in groups for row in group]
    return rows
