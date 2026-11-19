"""Vendor collectors: how to fake each vendor so its collector answers real agent expectations.

A spec says how to point the collector at ofapi, which vendor answers to script for a verdict
(built from the signals of the expectations the agent just produced), what the collector must
report to OpenAEV, and which vendor calls it must have made. ``recipes.vendor_collector`` runs
any spec end to end.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime

from staticfire.fakes import Ofapi


# What the agent run produced, as a vendor would see it
@dataclass
class Signals:
    inject_id: str
    agent_id: str
    asset_id: str
    hostname: str
    implant: str
    start: datetime
    end: datetime
    ips: list[str]

    @property
    def end_ms(self) -> int:
        return int(self.end.timestamp() * 1000)

    @property
    def start_ms(self) -> int:
        return int(self.start.timestamp() * 1000)

    @property
    def end_iso(self) -> str:
        return self.end.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"

    @property
    def start_iso(self) -> str:
        return self.start.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"

    @property
    def ipv4(self) -> str:
        """The endpoint's own address (not a Docker bridge)."""
        candidates = [ip for ip in self.ips if "." in ip and not ip.startswith("172.")]
        return (candidates or [ip for ip in self.ips if "." in ip] or ["127.0.0.1"])[0]


@dataclass
class Rule:
    """One scripted vendor answer: every call to the path prefix gets this body."""

    path: str
    body: object
    method: str | None = None
    status: int = 200
    # A str body is sent raw with this content type (XML, NDJSON...), anything else as JSON
    content_type: str = "application/json"

    def response(self) -> dict:
        if isinstance(self.body, str):
            return {"status": self.status, "text": self.body, "content_type": self.content_type}
        return {"status": self.status, "body": self.body}


# verdict -> expected result text per expectation type (None: must stay unanswered)
DETECT_AND_PREVENT = {
    "prevented": {"DETECTION": "Detected", "PREVENTION": "Prevented"},
    "detected": {"DETECTION": "Detected", "PREVENTION": None},
    "none": {"DETECTION": None, "PREVENTION": None},
}
DETECT_ONLY = {
    "detected": {"DETECTION": "Detected", "PREVENTION": None},
    "none": {"DETECTION": None, "PREVENTION": None},
}


@dataclass
class VendorCollector:
    recipe: str
    collector: str  # directory in the collectors repository
    env: Callable[[Ofapi], dict[str, str]]
    rules: Callable[[Signals, str], list[Rule]]
    expected: dict[str, dict[str, str | None]] = field(default_factory=lambda: DETECT_AND_PREVENT)
    # Path prefixes the collector must have called on the fake
    calls: list[str] = field(default_factory=list)
    period: str = "PT15S"
    description: str = ""

    @property
    def verdicts(self) -> list[str]:
        return list(self.expected)


# -- Palo Alto Cortex XDR --

XDR_ALERTS = "/palo-alto-cortex-xdr/public_api/v1/alerts/get_alerts_multi_events"


def _xdr_rules(s: Signals, verdict: str) -> list[Rule]:
    actions = {
        "prevented": ["Detected (Reported)", "Prevented (Blocked)"],
        "detected": ["Detected (Reported)"],
        "none": [],
    }[verdict]
    alerts = [
        {
            "external_id": f"staticfire-{i}",
            "severity": "high",
            "matching_status": "MATCHED",
            "case_id": None,
            "alert_id": i,
            "actor_process_command_line": s.implant,
            "category": "Malware",
            "description": "Alert scripted by staticfire",
            "action": action.split(" ")[0].upper(),
            "action_pretty": action,
            "detection_timestamp": s.end_ms,
            # The implant in the events lets the collector match without enrichment calls
            "events": [{"actor_process_image_name": s.implant}],
        }
        for i, action in enumerate(actions, start=1)
    ]
    reply = {"total_count": len(alerts), "result_count": len(alerts), "alerts": alerts}
    return [Rule(XDR_ALERTS, {"reply": reply})]


CORTEX_XDR = VendorCollector(
    recipe="cortex-xdr",
    collector="palo-alto-cortex-xdr",
    env=lambda fake: {
        # The client hardcodes https://{fqdn}: the fake's TLS port, trusted through the CA bundle
        "PALO_ALTO_CORTEX_XDR_FQDN": fake.url("palo-alto-cortex-xdr"),
        "PALO_ALTO_CORTEX_XDR_API_KEY": "staticfire-fake-key",
        "PALO_ALTO_CORTEX_XDR_API_KEY_ID": "1",
        "REQUESTS_CA_BUNDLE": str(fake.cert),
    },
    rules=_xdr_rules,
    calls=[XDR_ALERTS],
    description="alerts naming the implant process, action Detected/Prevented",
)


# -- SIEMs --
# The five SIEM collectors rebuild the implant from the URL the agent fetched its payload from,
# answer DETECTION only, and report "Not Detected" once their retries find nothing.

SIEM = {
    "detected": {"DETECTION": "Detected", "PREVENTION": None},
    "none": {"DETECTION": "Not Detected", "PREVENTION": None},
}
# Fast settings for any SIEM: no retry on an empty or non-matching answer
SIEM_FAST = {"MAX_RETRY": "0", "OFFSET": "PT5S"}


def _payload_path(s: Signals) -> str:
    """The URL path an agent downloads the implant from, which SIEMs log."""
    return f"/api/injects/{s.inject_id}/{s.agent_id}/executable-payload"


def _siem_env(prefix: str, vendor: str, auth: dict[str, str]):
    def env(fake: Ofapi) -> dict[str, str]:
        settings = {f"{prefix}_BASE_URL": fake.http_url(vendor)}
        settings.update({f"{prefix}_{k}": v for k, v in {**SIEM_FAST, **auth}.items()})
        return settings

    return env


ELASTIC_SEARCH = "^/elastic/.+/_search$"


def _elastic_rules(s: Signals, verdict: str) -> list[Rule]:
    hits = []
    if verdict == "detected":
        # A network-style row: with host.name and a pid the collector would drill down instead
        hits = [
            {
                "_id": "staticfire-1",
                "_source": {
                    "@timestamp": s.end_iso,
                    "url.path": _payload_path(s),
                    "kibana.alert.rule.name": "staticfire scripted alert",
                },
            }
        ]
    body = {
        "took": 1,
        "timed_out": False,
        "hits": {"total": {"value": len(hits), "relation": "eq"}, "hits": hits},
    }
    return [Rule(ELASTIC_SEARCH, body, method="POST")]


ELASTIC = VendorCollector(
    recipe="elastic",
    collector="elastic",
    env=_siem_env("ELASTIC", "elastic", {"API_KEY": "staticfire-fake-key"}),
    rules=_elastic_rules,
    expected=SIEM,
    calls=["/elastic/"],
    description="a security alert whose url.path is the implant download",
)

LOGRHYTHM_RESULTS = "/logrhythm/lr-search-api/actions/search-result"


def _logrhythm_rules(s: Signals, verdict: str) -> list[Rule]:
    items = []
    if verdict == "detected":
        items = [
            {
                "normalDateMin": s.end_iso,
                "url": _payload_path(s),
                "commonEventName": "staticfire scripted event",
            }
        ]
    return [Rule(LOGRHYTHM_RESULTS, {"TaskStatus": "Completed", "Items": items}, method="POST")]


LOGRHYTHM = VendorCollector(
    recipe="logrhythm",
    collector="logrhythm",
    env=_siem_env("LOGRHYTHM", "logrhythm", {"TOKEN": "staticfire-fake-token"}),
    rules=_logrhythm_rules,
    expected=SIEM,
    calls=["/logrhythm/lr-search-api/actions/search-task", LOGRHYTHM_RESULTS],
    description="a search result whose url is the implant download",
)

NETWITNESS_SDK = "/netwitness/sdk"


def _netwitness_rules(s: Signals, verdict: str) -> list[Rule]:
    fields = []
    if verdict == "detected":
        fields = [
            {"group": 1, "type": "time", "value": s.end_iso},
            {"group": 1, "type": "url", "value": _payload_path(s)},
        ]
    return [Rule(NETWITNESS_SDK, {"results": {"fields": fields}}, method="GET")]


NETWITNESS = VendorCollector(
    recipe="netwitness",
    collector="netwitness",
    env=_siem_env("NETWITNESS", "netwitness", {"TOKEN": "staticfire-fake-token"}),
    rules=_netwitness_rules,
    expected=SIEM,
    calls=[NETWITNESS_SDK],
    description="SDK query meta whose url is the implant download",
)

QRADAR_RESULTS = "^/qradar/api/ariel/searches/[^/]+/results$"


def _qradar_rules(s: Signals, verdict: str) -> list[Rule]:
    events = []
    if verdict == "detected":
        events = [
            {
                "starttime": s.end_ms,
                "URL": _payload_path(s),
                "qidname": "staticfire scripted event",
            }
        ]
    return [Rule(QRADAR_RESULTS, {"events": events}, method="GET")]


QRADAR = VendorCollector(
    recipe="qradar",
    collector="qradar",
    env=_siem_env("QRADAR", "qradar", {"TOKEN": "staticfire-fake-token"}),
    rules=_qradar_rules,
    expected=SIEM,
    calls=["/qradar/api/ariel/searches"],
    description="an Ariel search event whose URL is the implant download",
)

SPLUNK_JOBS = "/splunk-es/services/search/jobs"


def _splunk_rules(s: Signals, verdict: str) -> list[Rule]:
    results = []
    if verdict == "detected":
        results = [
            {
                "_time": s.end_iso,
                "host": s.hostname,
                "_raw": f"process start parent={s.implant} host={s.hostname}",
            }
        ]
    return [Rule(SPLUNK_JOBS, {"results": results}, method="POST")]


SPLUNK_ES = VendorCollector(
    recipe="splunk-es",
    collector="splunk-es",
    env=_siem_env(
        "SPLUNKES", "splunk-es", {"USERNAME": "staticfire", "PASSWORD": "staticfire-fake"}
    ),
    rules=_splunk_rules,
    expected=SIEM,
    calls=[SPLUNK_JOBS],
    description="a notable whose raw event names the implant process",
)


# -- EDR / XDR --

CROWDSTRIKE_QUERY = "/crowdstrike/alerts/queries/alerts/v2"
CROWDSTRIKE_ENTITIES = "/crowdstrike/alerts/entities/alerts/v2"
# pattern_disposition bitmask: 2048 = process blocked, 0 = detection only
CROWDSTRIKE_BLOCKED = 2048


def _crowdstrike_rules(s: Signals, verdict: str) -> list[Rule]:
    if verdict == "none":
        return [Rule(CROWDSTRIKE_QUERY, {"errors": [], "meta": {}, "resources": []}, method="GET")]
    alert_id = "staticfire-1"
    entity = {
        "id": alert_id,
        "composite_id": f"cid:ind:{alert_id}",
        "filename": s.implant,
        "parent_details": {"filename": "sh"},
        "grandparent_details": {"filename": "openaev-agent"},
        "device": {"hostname": s.hostname},
        "pattern_disposition": CROWDSTRIKE_BLOCKED if verdict == "prevented" else 0,
        "display_name": "Alert scripted by staticfire",
        "created_timestamp": s.end_iso,
        "updated_timestamp": s.end_iso,
    }
    return [
        Rule(
            CROWDSTRIKE_QUERY,
            {"errors": [], "meta": {}, "resources": [entity["composite_id"]]},
            method="GET",
        ),
        Rule(
            CROWDSTRIKE_ENTITIES, {"errors": [], "meta": {}, "resources": [entity]}, method="POST"
        ),
    ]


CROWDSTRIKE = VendorCollector(
    recipe="crowdstrike",
    collector="crowdstrike",
    env=lambda fake: {
        "CROWDSTRIKE_API_BASE_URL": fake.http_url("crowdstrike"),
        "CROWDSTRIKE_UI_BASE_URL": "https://falcon.example",
        "CROWDSTRIKE_CLIENT_ID": "staticfire-client",
        "CROWDSTRIKE_CLIENT_SECRET": "staticfire-fake-secret",
        # Required by its settings, although its README documents a default
        "COLLECTOR_NAME": "CrowdStrike Endpoint Security",
    },
    rules=_crowdstrike_rules,
    # A matching alert that did not block it is reported as such, not left pending
    expected={
        "prevented": {"DETECTION": "Detected", "PREVENTION": "Prevented"},
        "detected": {"DETECTION": "Detected", "PREVENTION": "Not Prevented"},
        "none": {"DETECTION": None, "PREVENTION": None},
    },
    calls=["/crowdstrike/oauth2/token", CROWDSTRIKE_QUERY],
    description="an ldt alert on the implant file, pattern_disposition 2048 when blocked",
)

SENTINELONE_THREATS = "^/sentinelone/web/api/v2.1/threats$"
SENTINELONE_EVENTS = "^/sentinelone/web/api/v2.1/threats/[^/]+/explore/events"


def _sentinelone_rules(s: Signals, verdict: str) -> list[Rule]:
    threats = []
    if verdict != "none":
        threats = [
            {
                "threatInfo": {"threatId": "staticfire-1", "sha1": "", "detectionType": "dynamic"},
                "agentRealtimeInfo": {"agentComputerName": s.hostname},
                "mitigationStatus": [{"status": "success"}] if verdict == "prevented" else [],
            }
        ]
    events = {"data": [{"parentProcessName": s.implant, "processName": "sh"}]}
    return [
        Rule(SENTINELONE_THREATS, {"data": threats}, method="GET"),
        Rule(SENTINELONE_EVENTS, events, method="GET"),
    ]


SENTINELONE = VendorCollector(
    recipe="sentinelone",
    collector="sentinelone",
    env=lambda fake: {
        "SENTINELONE_BASE_URL": fake.http_url("sentinelone"),
        "SENTINELONE_API_KEY": "staticfire-fake-key",
        # The unified alerts GraphQL API has no fake: threats and their events are enough
        "SENTINELONE_ENABLE_ALERTS": "false",
    },
    rules=_sentinelone_rules,
    calls=["/sentinelone/web/api/v2.1/threats"],
    description="a threat whose events name the implant as parent process, mitigated when blocked",
)

TANIUM_ALERTS = "/tanium/plugin/products/threat-response/api/v1/alerts"


def _tanium_rules(s: Signals, verdict: str) -> list[Rule]:
    alerts = []
    if verdict == "detected":
        details = {
            "finding": {
                "first_seen": s.end_iso,
                "whats": [
                    {
                        "artifact_activity": {
                            "acting_artifact": {
                                "process": {"file": {"file": {"path": f"/tmp/{s.implant}"}}}
                            }
                        }
                    }
                ],
            }
        }
        alerts = [
            {
                "guid": "staticfire-1",
                "createdAt": s.end_iso,
                "state": "unresolved",
                "matchType": "intel",
                "host": s.hostname,
                "ip": s.ipv4,
                "details": json.dumps(details),
            }
        ]
    return [Rule(TANIUM_ALERTS, {"data": alerts}, method="GET")]


TANIUM = VendorCollector(
    recipe="tanium",
    collector="tanium-threat-response",
    env=lambda fake: {
        "COLLECTOR_TANIUM_URL": fake.http_url("tanium"),
        "COLLECTOR_TANIUM_URL_CONSOLE": "https://tanium.example",
        "COLLECTOR_TANIUM_TOKEN": "staticfire-fake-token",
        "COLLECTOR_TANIUM_SSL_VERIFY": "false",
    },
    rules=_tanium_rules,
    expected=DETECT_ONLY,
    calls=[TANIUM_ALERTS],
    description="a Threat Response alert whose acting process is the implant",
)

XSOAR_SEARCH = "/palo-alto-cortex-xsoar/xsoar/public/v1/incidents/search"


def _xsoar_rules(s: Signals, verdict: str) -> list[Rule]:
    incidents = []
    if verdict != "none":
        prevented = verdict == "prevented"
        incidents = [
            {
                "id": "staticfire-1",
                "CustomFields": {
                    "xdralerts": [
                        {
                            "alert_id": "staticfire-1",
                            # Matched on time: inside the expectation's start/end window
                            "detection_timestamp": (s.start_ms + s.end_ms) // 2,
                            "action_pretty": "Prevented (Blocked)"
                            if prevented
                            else "Detected (Reported)",
                            "action": "Prevented" if prevented else "Reported",
                            "actor_process_image_name": s.implant,
                            "actor_process_command_line": s.implant,
                        }
                    ]
                },
            }
        ]
    return [Rule(XSOAR_SEARCH, {"total": len(incidents), "data": incidents}, method="POST")]


CORTEX_XSOAR = VendorCollector(
    recipe="cortex-xsoar",
    collector="palo-alto-cortex-xsoar",
    env=lambda fake: {
        "PALO_ALTO_CORTEX_XSOAR_API_URL": fake.http_url("palo-alto-cortex-xsoar"),
        "PALO_ALTO_CORTEX_XSOAR_API_KEY": "staticfire-fake-key",
        "PALO_ALTO_CORTEX_XSOAR_API_KEY_ID": "1",
    },
    rules=_xsoar_rules,
    calls=[XSOAR_SEARCH],
    description="an incident with an XDR alert inside the expectation's time window",
)


SPECS: dict[str, VendorCollector] = {
    spec.recipe: spec
    for spec in [
        CORTEX_XDR,
        CORTEX_XSOAR,
        CROWDSTRIKE,
        SENTINELONE,
        TANIUM,
        ELASTIC,
        LOGRHYTHM,
        NETWITNESS,
        QRADAR,
        SPLUNK_ES,
    ]
}
