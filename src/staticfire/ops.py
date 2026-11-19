"""The operations staticfire offers, shared by the CLI and the MCP server.

Every function takes a Profile and returns plain JSON-friendly data, so the same result can be
printed for a human or handed to a model.
"""

from __future__ import annotations

import json
import time
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from staticfire import runner
from staticfire.config import Profile
from staticfire.mailpit import Mailpit
from staticfire.openaev import (
    TERMINAL_EXERCISE_STATUSES,
    TERMINAL_INJECT_STATUSES,
    OpenAEV,
    OpenAEVError,
    wait_until,
)

MARKER_PAYLOAD_NAME = "staticfire - echo marker"
TECHNICAL_EXPECTATIONS = ("DETECTION", "PREVENTION")
# Signature types that only repeat the endpoint's network interfaces: noise in a summary
NETWORK_SIGNATURES = {
    "source_ipv4_address",
    "source_ipv6_address",
    "target_ipv4_address",
    "target_ipv6_address",
}


def parse_date(value: str) -> datetime:
    """OpenAEV dates carry nanoseconds, which datetime cannot parse: keep microseconds."""
    value = value.replace("Z", "+00:00")
    if "." in value:
        head, tail = value.split(".", 1)
        digits = "".join(ch for ch in tail if ch.isdigit())
        value = f"{head}.{digits[:6]}{tail[len(digits) :]}"
    parsed = datetime.fromisoformat(value)
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)


def client(profile: Profile) -> OpenAEV:
    return OpenAEV(profile.openaev_url, profile.openaev_token)


def mailpit(profile: Profile) -> Mailpit:
    if not profile.mailpit_url:
        raise ValueError(f"Profile {profile.name} has no mailpit_url")
    return Mailpit(profile.mailpit_url)


def ui_link(profile: Profile, kind: str, entity_id: str) -> str:
    return f"{profile.openaev_url}/admin/{kind}/{entity_id}"


# -- platform --


# Collectors age expectations by their creation date: a platform clock off by more than this
# makes fresh expectations look expired (or not yet started)
MAX_CLOCK_SKEW = 120


def clock_problem(profile: Profile) -> str | None:
    """Why the platform clock cannot be trusted for collector tests, if it cannot."""
    skew = client(profile).clock_skew()
    if abs(skew) <= MAX_CLOCK_SKEW:
        return None
    fix = (
        f"multipass exec {profile.multipass_vm} -- sudo chronyc makestep"
        if profile.multipass_vm
        else "resynchronise the platform host's clock (chronyc makestep)"
    )
    return f"platform clock is {skew:+.0f}s off this machine's: {fix}"


def status(profile: Profile) -> dict:
    api = client(profile)
    settings = api.settings()
    result: dict[str, Any] = {
        "profile": profile.public(),
        "platform": {
            "version": settings.get("platform_version"),
            "base_url": settings.get("platform_base_url"),
            "clock_skew_s": round(api.clock_skew(), 1),
            "clock_problem": clock_problem(profile),
        },
        "injectors": [
            {
                "id": i["injector_id"],
                "name": i.get("injector_name"),
                "type": i.get("injector_type"),
                "external": i.get("injector_external"),
            }
            for i in api.injectors()
        ],
        "collectors": [
            {
                "id": c["collector_id"],
                "name": c.get("collector_name"),
                "type": c.get("collector_type"),
                "last_execution": c.get("collector_last_execution"),
            }
            for c in api.collectors()
        ],
        "endpoints": [endpoint_summary(e) for e in api.endpoints()],
        "runs": [r.summary() for r in runner.list_runs()],
    }
    if profile.mailpit_url:
        try:
            info = mailpit(profile).info()
            result["mailpit"] = {"url": profile.mailpit_url, "messages": info.get("Messages")}
        except Exception as err:  # reported, not fatal: only email tests need it
            result["mailpit"] = {"url": profile.mailpit_url, "error": str(err)}
    return result


def endpoint_summary(endpoint: dict) -> dict:
    return {
        "asset_id": endpoint["asset_id"],
        "name": endpoint.get("asset_name"),
        "platform": endpoint.get("endpoint_platform"),
        "arch": endpoint.get("endpoint_arch"),
        "agents": [
            {
                "agent_id": a.get("agent_id"),
                "active": a.get("agent_active"),
                "user": a.get("agent_executed_by_user"),
                "last_seen": a.get("agent_last_seen"),
            }
            for a in endpoint.get("asset_agents") or []
        ],
    }


def agent_endpoint(profile: Profile, asset_id: str | None = None) -> dict:
    """The endpoint to target: the given one, or the first one with an active agent."""
    endpoints = [endpoint_summary(e) for e in client(profile).endpoints()]
    if asset_id:
        found = next((e for e in endpoints if e["asset_id"] == asset_id), None)
        if not found:
            raise ValueError(f"No endpoint {asset_id}")
        return found
    for endpoint in endpoints:
        if any(a["active"] for a in endpoint["agents"]):
            return endpoint
    raise ValueError(
        "No endpoint with an active agent: install one (liftoff installs it on the platform VM)"
    )


# -- injectors and collectors under test --


def component_up(
    profile: Profile,
    path: str,
    kind: str | None = None,
    env: dict[str, str] | None = None,
    pyoaev: str | None = None,
    install: str = "auto",
    restart: bool = True,
    log_level: str = "info",
    timeout: float = 120,
    python_version: str | None = None,
) -> dict:
    """Install (if needed), start and wait for an injector/collector to register."""
    component = runner.detect(path, kind)
    run_name = f"{component.kind}-{component.name}"
    install_output = None
    if (
        install == "always"
        or (install == "auto" and not component.installed)
        or pyoaev
        or python_version
    ):
        install_output = runner.install(component, pyoaev=pyoaev, python_version=python_version)
    if restart:
        runner.stop(run_name)
    elif (existing := runner.get_run(run_name)) and existing.alive:
        return {"component": component.__dict__, "run": existing.summary(), "reused": True}
    run = runner.start(component, profile, env, run_name=run_name, log_level=log_level)
    api = client(profile)
    registered, entity = wait_until(
        lambda: _registered(api, component) if run.alive else "died", timeout, 2
    )
    result: dict[str, Any] = {
        "component": {**component.__dict__, "id": component.component_id},
        "run": run.summary(),
        "registered": registered and entity != "died",
    }
    if result["registered"]:
        result["entity"] = entity
        if component.kind == "injector":
            result["contracts"] = injector_contracts(profile, component.component_id)
    else:
        result["log_tail"] = runner.tail(run_name, 40)
    if install_output:
        result["installed"] = True
    return result


def _registered(api: OpenAEV, component: runner.Component) -> dict | None:
    try:
        if component.kind == "injector":
            injector = api.injector(component.component_id)
            # Registration is only usable once the contracts are in
            if not api.injector_contracts(component.component_id):
                return None
            return {
                "id": injector["injector_id"],
                "name": injector.get("injector_name"),
                "type": injector.get("injector_type"),
            }
        collector = next(
            (c for c in api.collectors() if c["collector_id"] == component.component_id), None
        )
        return collector and {
            "id": collector["collector_id"],
            "name": collector.get("collector_name"),
            "type": collector.get("collector_type"),
        }
    except OpenAEVError:
        return None


def component_down(target: str) -> dict:
    run_name = _run_name(target)
    return {"run": run_name, "stopped": runner.stop(run_name)}


def component_logs(target: str, lines: int = 80, grep: str | None = None) -> str:
    return runner.tail(_run_name(target), lines, grep)


def _run_name(target: str) -> str:
    """Accept a run name or the path of the component it runs."""
    if runner.get_run(target):
        return target
    if Path(target).expanduser().exists():
        component = runner.detect(target)
        return f"{component.kind}-{component.name}"
    raise ValueError(f"No run named {target}; known: {[r.run_name for r in runner.list_runs()]}")


def injector_contracts(profile: Profile, injector_id: str) -> list[dict]:
    return [
        {
            "contract_id": contract["contract_id"],
            "label": (contract.get("label") or {}).get("en"),
            "fields": [
                {
                    "key": f["key"],
                    "type": f.get("type"),
                    "mandatory": f.get("mandatory"),
                    "default": f.get("defaultValue"),
                }
                for f in contract.get("fields") or []
            ],
        }
        for contract in client(profile).injector_contracts(injector_id)
    ]


def resolve_injector(profile: Profile, ref: str) -> str:
    """Injector id from an id, a registered type (openaev_email_smtp) or a checkout path."""
    if Path(ref).expanduser().exists():
        return runner.detect(ref).component_id
    for injector in client(profile).injectors():
        if ref in (injector["injector_id"], injector.get("injector_type")):
            return injector["injector_id"]
    raise ValueError(f"Unknown injector {ref}")


# -- injects --


# Field types whose value the inject carries outside the content, or that staticfire builds itself
NON_CONTENT_FIELDS = {"expectation", "team", "asset", "asset-group", "attachment", "article"}


def contract_defaults(api: OpenAEV, contract_id: str) -> dict:
    """Default value of every content field, as the UI form starts with them."""
    try:
        contract = api.injector_contract(contract_id)
        fields = json.loads(contract.get("injector_contract_content") or "{}").get("fields", [])
    except (OpenAEVError, ValueError):
        return {}
    return {
        f["key"]: _form_value(f)
        for f in fields
        if f.get("type") not in NON_CONTENT_FIELDS and f.get("defaultValue") is not None
    }


def _form_value(field: dict) -> Any:
    """The UI form (InjectContentForm) sends the first default of a single-value field: the
    platform rejects a list there (a choice sent as ['plain-text'] breaks payload generation)."""
    default = field["defaultValue"]
    if isinstance(default, list) and field.get("cardinality") == "1":
        return default[0] if default else ""
    return default


def expectation_content(types: list[str] | tuple[str, ...], expiration: int = 3600) -> list[dict]:
    return [
        {
            "expectation_type": t.upper(),
            "expectation_name": t.title(),
            "expectation_score": 100,
            "expectation_expectation_group": False,
            "expectation_expiration_time": expiration,
        }
        for t in types
    ]


def run_inject(
    profile: Profile,
    contract_id: str,
    content: dict | None = None,
    assets: list[str] | None = None,
    asset_groups: list[str] | None = None,
    teams: list[str] | None = None,
    expectations: list[str] | None = None,
    title: str | None = None,
    timeout: float = 180,
    launch: bool = True,
    defaults: bool = True,
) -> dict:
    """Create an atomic testing, launch it and wait for its execution to end.

    Fields missing from ``content`` get the contract's default value (as in the UI form), unless
    ``defaults`` is off: injectors read optional fields without checking they are present.
    """
    api = client(profile)
    content = {**(contract_defaults(api, contract_id) if defaults else {}), **(content or {})}
    if expectations:
        content["expectations"] = expectation_content(expectations)
    created = api.create_atomic_testing(
        {
            "inject_title": title or f"staticfire {uuid.uuid4().hex[:8]}",
            "inject_injector_contract": contract_id,
            "inject_content": content,
            "inject_assets": assets or [],
            "inject_asset_groups": asset_groups or [],
            "inject_teams": teams or [],
        }
    )
    inject_id = created["inject_id"]
    if not launch:
        return {
            "inject_id": inject_id,
            "link": ui_link(profile, "atomic_testings", inject_id),
            "status": (created.get("inject_status") or {}).get("status_name"),
        }
    return launch_and_wait(profile, inject_id, assets, timeout)


def launch_and_wait(
    profile: Profile, inject_id: str, assets: list[str] | None = None, timeout: float = 180
) -> dict:
    """Launch an existing atomic testing and report it once its execution ended."""
    api = client(profile)
    api.launch_atomic_testing(inject_id)
    finished, _ = wait_until(lambda: _terminal_status(api, inject_id), timeout, 3)
    result: dict[str, Any] = {"link": ui_link(profile, "atomic_testings", inject_id)}
    result.update(inject_report(profile, inject_id, assets or []))
    result["finished"] = finished
    return result


def _terminal_status(api: OpenAEV, inject_id: str) -> dict | None:
    current = api.atomic_testing(inject_id).get("inject_status") or {}
    return current if current.get("status_name") in TERMINAL_INJECT_STATUSES else None


def inject_report(profile: Profile, inject_id: str, assets: list[str] | None = None) -> dict:
    """Status, execution traces and expectation results of an inject, per targeted asset."""
    api = client(profile)
    inject_status = api.inject_status(inject_id) or {}
    report: dict[str, Any] = {
        "inject_id": inject_id,
        "status": inject_status.get("status_name"),
        "traces": [
            {
                "status": t.get("execution_status"),
                "action": t.get("execution_action"),
                "message": t.get("execution_message"),
                "time": t.get("execution_time"),
            }
            for t in inject_status.get("status_main_traces") or []
        ],
        # One summary per expectation type the inject carries: drop those of types it has none of
        "expectation_results": [
            r
            for r in api.atomic_testing(inject_id).get("inject_expectation_results") or []
            if any(d.get("value") for d in r.get("distribution") or [])
        ],
    }
    if assets:
        report["targets"] = {
            asset: {
                "traces": _asset_traces(api, inject_id, asset),
                "expectations": expectations_of_target(api, inject_id, asset),
            }
            for asset in assets
        }
    return report


def _asset_traces(api: OpenAEV, inject_id: str, asset_id: str) -> list[dict]:
    try:
        traces = api.inject_traces(inject_id, asset_id, "ASSETS")
    except OpenAEVError:
        return []
    return [
        {
            "status": t.get("execution_status"),
            "action": t.get("execution_action"),
            "message": t.get("execution_message"),
            "agent": t.get("execution_agent"),
        }
        for t in traces or []
    ]


def expectations_of_target(api: OpenAEV, inject_id: str, asset_id: str) -> list[dict]:
    try:
        entries = api.target_results(inject_id, asset_id, "ASSETS")
    except OpenAEVError:
        return []
    return [
        {
            "id": e.get("inject_expectation_id"),
            "type": e.get("inject_expectation_type"),
            "status": e.get("inject_expectation_status"),
            "score": e.get("inject_expectation_score"),
            "agent": e.get("inject_expectation_agent"),
            "results": [
                {
                    "source_id": r.get("sourceId"),
                    "source": r.get("sourceName"),
                    "source_type": r.get("sourceType"),
                    "platform": r.get("sourcePlatform"),
                    "result": r.get("result"),
                    "score": r.get("score"),
                    "metadata": r.get("metadata"),
                }
                for r in e.get("inject_expectation_results") or []
            ],
        }
        for e in entries
    ]


def inject_findings(profile: Profile, inject_id: str) -> list[dict]:
    """Findings the platform created from the inject's structured outputs."""
    page = client(profile).post(
        f"/api/findings/injects/{inject_id}/search", {"page": 0, "size": 100}
    )
    return [
        {
            "type": f.get("finding_type"),
            "field": f.get("finding_field"),
            "value": f.get("finding_value"),
            "assets": [
                a.get("asset_id") for a in f.get("finding_assets") or [] if isinstance(a, dict)
            ],
        }
        for f in (page or {}).get("content", [])
    ]


def pending_expectations(profile: Profile, inject_id: str | None = None) -> list[dict]:
    """Agent expectations not answered yet, as a collector polling OpenAEV receives them.

    Read through a source id that never answers, so every pending expectation shows.
    """
    probe = str(uuid.uuid5(runner.ID_NAMESPACE, "staticfire:probe-source"))
    expectations = client(profile).expectations_for_source(probe)
    if inject_id:
        expectations = [e for e in expectations if e.get("inject_expectation_inject") == inject_id]
    return [
        {
            "id": e["inject_expectation_id"],
            "type": e.get("inject_expectation_type"),
            "inject": e.get("inject_expectation_inject"),
            "agent": e.get("inject_expectation_agent"),
            "asset": e.get("inject_expectation_asset"),
            "created_at": e.get("inject_expectation_created_at"),
            "signatures": [
                s
                for s in e.get("inject_expectation_signatures") or []
                if s.get("type") not in NETWORK_SIGNATURES
            ],
            "network_signatures": sorted(
                {
                    s["value"]
                    for s in e.get("inject_expectation_signatures") or []
                    if s.get("type") in NETWORK_SIGNATURES
                }
            ),
        }
        for e in expectations
    ]


def wait_expectations(
    profile: Profile,
    inject_id: str,
    asset_id: str,
    source_id: str | None = None,
    types: tuple[str, ...] = TECHNICAL_EXPECTATIONS,
    timeout: float = 180,
) -> tuple[bool, list[dict]]:
    """Wait until every agent expectation of these types has a result (from ``source_id``)."""
    api = client(profile)

    def answered() -> list[dict] | None:
        expectations = [
            e for e in expectations_of_target(api, inject_id, asset_id) if e["type"] in types
        ]
        if not expectations:
            return None
        for expectation in expectations:
            sources = [r for r in expectation["results"] if r["result"]]
            if source_id:
                sources = [r for r in sources if r["source_id"] == source_id]
            if not sources:
                return None
        return expectations

    done, value = wait_until(answered, timeout, 5)
    return done, value or expectations_of_target(api, inject_id, asset_id)


def marker_contract(profile: Profile) -> str:
    """Contract of a harmless Linux/macOS command payload, created once: ``echo <marker>``."""
    api = client(profile)
    search = {"page": 0, "size": 20, "textSearch": MARKER_PAYLOAD_NAME}
    payload = next(
        (
            p
            for p in api.post("/api/payloads/search", search).get("content", [])
            if p.get("payload_name") == MARKER_PAYLOAD_NAME
        ),
        None,
    )
    if not payload:
        payload = api.post(
            "/api/payloads",
            {
                "payload_type": "Command",
                "payload_name": MARKER_PAYLOAD_NAME,
                "payload_description": "Created by staticfire to give collectors real agent "
                "expectations: prints a marker, nothing else.",
                "payload_source": "MANUAL",
                "payload_status": "VERIFIED",
                "payload_platforms": ["Linux", "MacOS"],
                "payload_execution_arch": "ALL_ARCHITECTURES",
                "payload_expectations": list(TECHNICAL_EXPECTATIONS),
                "command_executor": "sh",
                "command_content": "echo staticfire-marker #{marker}",
                "payload_arguments": [{"type": "text", "key": "marker", "default_value": "none"}],
                "payload_domains": [],
            },
        )
    contracts = api.post(
        "/api/injector_contracts/search",
        {
            "page": 0,
            "size": 5,
            "include_full_details": False,
            "filterGroup": {
                "mode": "and",
                "filters": [
                    {
                        "key": "injector_contract_payload",
                        "operator": "eq",
                        "mode": "or",
                        "values": [payload["payload_id"]],
                    }
                ],
            },
        },
    ).get("content", [])
    if not contracts:
        raise RuntimeError(f"No injector contract for payload {payload['payload_id']}")
    return contracts[0]["injector_contract_id"]


def agent_expectations(
    profile: Profile,
    asset_id: str | None = None,
    types: list[str] | None = None,
    marker: str | None = None,
    timeout: float = 180,
) -> dict:
    """Make the agent run a marker command so collectors have real expectations to answer."""
    endpoint = agent_endpoint(profile, asset_id)
    marker = marker or uuid.uuid4().hex[:12]
    result = run_inject(
        profile,
        marker_contract(profile),
        content={"marker": marker},
        assets=[endpoint["asset_id"]],
        expectations=types or list(TECHNICAL_EXPECTATIONS),
        title=f"staticfire agent expectations {marker}",
        timeout=timeout,
    )
    result["endpoint"] = endpoint
    result["marker"] = marker
    result["pending"] = pending_expectations(profile, result["inject_id"])
    return result


# -- scenarios --


def launch_scenario(profile: Profile, scenario_id: str, timeout: float = 600) -> dict:
    """Start a simulation of the scenario and wait for all its injects to be executed."""
    api = client(profile)
    simulation = api.launch_scenario(scenario_id)
    simulation_id = simulation["exercise_id"]

    def settled() -> list[dict] | None:
        exercise = api.exercise(simulation_id)
        injects = api.exercise_injects(simulation_id)
        statuses = [(i.get("inject_status") or {}).get("status_name") for i in injects]
        if exercise.get("exercise_status") in TERMINAL_EXERCISE_STATUSES or (
            injects and all(s in TERMINAL_INJECT_STATUSES for s in statuses)
        ):
            return injects
        return None

    finished, injects = wait_until(settled, timeout, 10)
    injects = injects or api.exercise_injects(simulation_id)
    exercise = api.exercise(simulation_id)
    return {
        "simulation_id": simulation_id,
        "link": ui_link(profile, "simulations", simulation_id),
        "status": exercise.get("exercise_status"),
        "finished": finished,
        "injects": [
            {
                "inject_id": i.get("inject_id"),
                "title": i.get("inject_title"),
                "status": (i.get("inject_status") or {}).get("status_name"),
            }
            for i in injects
        ],
    }


# -- mail --


def mail_search(profile: Profile, query: str, limit: int = 20) -> list[dict]:
    box = mailpit(profile)
    return [box.describe(m["ID"]) for m in box.search(query, limit)]


def dumps(data: Any) -> str:
    return json.dumps(data, indent=2, default=str)


def now_marker() -> str:
    return time.strftime("%H%M%S") + uuid.uuid4().hex[:6]
