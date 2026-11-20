"""Vendor collectors: how to fake each vendor so its collector answers real agent expectations.

A spec says how to point the collector at ofapi, which vendor answers to script for a verdict
(built from the signals of the expectations the agent just produced), what the collector must
report to OpenAEV, and which vendor calls it must have made. ``recipes.vendor_collector`` runs
any spec end to end.
"""

from __future__ import annotations

import json
import zlib
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
    # Email injects: the delivered message (from, to, cc, subject, urls, message_id, date)
    email: dict = field(default_factory=dict)
    # SIEM chained after an EDR collector: that EDR's recipe, and the alertId it recorded
    edr: str = ""
    edr_alert_ids: list[str] = field(default_factory=list)

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
    # Send its HTTP(S) through the proxy to ofapi (hardcoded vendor hosts, SDKs)
    proxy: bool = False
    # Email security collector: the expectations come from an email-smtp inject (delivered to
    # mailpit, its implant name in a body URL) instead of the agent's marker command
    email: bool = False
    # A SIEM matching what an EDR collector answered: that EDR's recipe, run first (same
    # verdict) on the same expectations
    edr: str = ""
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


def _crowdstrike_meta(total: int) -> dict:
    # falconpy hands back an empty body when the API's meta is empty: always send a real one
    return {
        "query_time": 0.01,
        "pagination": {"offset": 0, "limit": 100, "total": total},
        "powered_by": "detectsapi",
        "trace_id": "staticfire",
    }


def _crowdstrike_rules(s: Signals, verdict: str) -> list[Rule]:
    if verdict == "none":
        body = {"errors": [], "meta": _crowdstrike_meta(0), "resources": []}
        return [Rule(CROWDSTRIKE_QUERY, body, method="GET")]
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
            {"errors": [], "meta": _crowdstrike_meta(1), "resources": [entity["composite_id"]]},
            method="GET",
        ),
        Rule(
            CROWDSTRIKE_ENTITIES,
            {"errors": [], "meta": _crowdstrike_meta(1), "resources": [entity]},
            method="POST",
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


# -- Microsoft (Graph security alerts, reached through the proxy) --
# The Microsoft collectors hardcode login.microsoftonline.com (MSAL) and graph.microsoft.com:
# the proxy hands both to ofapi (microsoft_identity, microsoft_graph), the rules below answer.

MS_TENANT = "6f1c2a4e-0b7d-4c55-9e3a-8d2f1b6c7a90"
MS_GRAPH_ALERTS = "/microsoft-graph/v1.0/security/alerts_v2"


def ms_token_path(tenant: str = MS_TENANT) -> str:
    return f"/microsoft-login/{tenant}/oauth2/v2.0/token"


def _ms_env(prefix: str, **extra: str) -> Callable[[Ofapi], dict[str, str]]:
    """Client-credentials settings of a Microsoft collector (its variables' prefix)."""

    def env(_fake: Ofapi) -> dict[str, str]:
        return {
            f"{prefix}TENANT_ID": MS_TENANT,
            f"{prefix}CLIENT_ID": "3c9e5f21-7a44-4d0e-8b6b-2f9d0c1e4a77",
            f"{prefix}CLIENT_SECRET": "staticfire~fake.secret-value",
            **extra,
        }

    return env


def _iso(moment: datetime, offset_s: float = 0) -> str:
    from datetime import timedelta

    return (moment + timedelta(seconds=offset_s)).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def graph_alert(
    alert_id: str,
    service_source: str,
    title: str,
    at: datetime,
    status: str,
    evidence: list[dict],
    detection_source: str | None = None,
) -> dict:
    """A Microsoft Graph security alert (alerts_v2) as Graph returns it."""
    return {
        "@odata.type": "#microsoft.graph.security.alert",
        "id": alert_id,
        "providerAlertId": alert_id.removeprefix("da"),
        "incidentId": str(zlib.crc32(alert_id.encode()) % 90000 + 10000),
        "status": status,
        "severity": "medium",
        "classification": "truePositive" if status == "resolved" else None,
        "determination": "malware" if status == "resolved" else None,
        "serviceSource": service_source,
        "detectionSource": detection_source or service_source,
        "productName": "Microsoft Defender for Endpoint",
        "detectorId": "7e5a1c4b-2d33-4f0a-9c8e-1b6d2f4a8e10",
        "tenantId": MS_TENANT,
        "title": title,
        "description": f"{title}. Alert raised by the staticfire scenario.",
        "recommendedActions": "Examine the process tree and the files it wrote.",
        "category": "Execution",
        "assignedTo": None,
        "alertWebUrl": f"https://security.microsoft.com/alerts/{alert_id}?tid={MS_TENANT}",
        "incidentWebUrl": f"https://security.microsoft.com/incident2/1/overview?tid={MS_TENANT}",
        "actorDisplayName": None,
        "threatDisplayName": None,
        "threatFamilyName": None,
        "mitreTechniques": ["T1059.004"],
        "createdDateTime": _iso(at, 20),
        "lastUpdateDateTime": _iso(at, 40),
        "resolvedDateTime": _iso(at, 40) if status == "resolved" else None,
        "firstActivityDateTime": _iso(at),
        "lastActivityDateTime": _iso(at, 5),
        "systemTags": [],
        "comments": [],
        "customDetails": {},
        "evidence": evidence,
    }


def _evidence(kind: str, at: datetime, status: str, **fields) -> dict:
    return {
        "@odata.type": f"#microsoft.graph.security.{kind}",
        "createdDateTime": _iso(at, 20),
        "verdict": "malicious",
        "remediationStatus": "prevented" if status == "prevented" else "active",
        "remediationStatusDetails": None,
        "roles": [],
        "detailedRoles": [],
        "tags": [],
        **fields,
    }


def device_evidence(at: datetime, status: str, hostname: str, ip: str) -> dict:
    return _evidence(
        "deviceEvidence",
        at,
        status,
        mdeDeviceId="4f8d2e6a1b3c5d7e9f0a2b4c6d8e0f1a3b5c7d9e",
        azureAdDeviceId=None,
        deviceDnsName=hostname,
        hostName=hostname,
        osPlatform="Linux",
        healthStatus="active",
        onboardingStatus="onboarded",
        lastIpAddress=ip,
        lastExternalIpAddress="203.0.113.24",
        ipInterfaces=[ip],
        loggedOnUsers=[{"accountName": "root", "domainName": hostname}],
    )


def process_evidence(at: datetime, status: str, image: str, parent: str, cmd: str) -> dict:
    def file(name: str) -> dict:
        return {
            "sha1": None,
            "sha256": None,
            "fileName": name,
            "filePath": "/tmp" if name.startswith("oaev") else "/usr/bin",
            "fileSize": 4096,
        }

    return _evidence(
        "processEvidence",
        at,
        status,
        detectionStatus=status,
        processId=48211,
        parentProcessId=48190,
        processCommandLine=cmd,
        processCreationDateTime=_iso(at),
        parentProcessCreationDateTime=_iso(at, -1),
        mdeDeviceId="4f8d2e6a1b3c5d7e9f0a2b4c6d8e0f1a3b5c7d9e",
        imageFile=file(image),
        parentProcessImageFile=file(parent),
        userAccount={"accountName": "root", "domainName": None, "userSid": None},
    )


def _noise_alert(service_source: str, at: datetime) -> dict:
    """An unrelated alert on another device: it must match no expectation."""
    return graph_alert(
        "da638650112233445566_-1029384756",
        service_source,
        "Suspicious PowerShell command line",
        at,
        "new",
        [
            device_evidence(at, "detected", "fin-laptop-07", "10.20.30.40"),
            process_evidence(
                at,
                "detected",
                "powershell.exe",
                "winword.exe",
                "powershell.exe -nop -w hidden -enc SQBFAFgA",
            ),
        ],
    )


def _defender_rules(s: Signals, verdict: str) -> list[Rule]:
    alerts = [_noise_alert("microsoftDefenderForEndpoint", s.end)]
    if verdict != "none":
        # The collector reads a prevention from the alert status (inProgress/resolved)
        status = "prevented" if verdict == "prevented" else "detected"
        alerts.insert(
            0,
            graph_alert(
                "da638650998877665544_1122334455",
                "microsoftDefenderForEndpoint",
                f"Suspicious process launched by {s.implant}",
                s.end,
                "resolved" if verdict == "prevented" else "new",
                [
                    device_evidence(s.end, status, s.hostname, s.ipv4),
                    process_evidence(s.end, status, "sh", s.implant, "sh -c 'echo marker'"),
                ],
            ),
        )
    body = {
        "@odata.context": "https://graph.microsoft.com/v1.0/$metadata#security/alerts_v2",
        "value": alerts,
    }
    return [Rule(MS_GRAPH_ALERTS, body, method="GET")]


MICROSOFT_DEFENDER = VendorCollector(
    recipe="microsoft-defender",
    collector="microsoft-defender",
    env=_ms_env("SOURCE_"),
    rules=_defender_rules,
    calls=[ms_token_path(), MS_GRAPH_ALERTS],
    proxy=True,
    description="Graph alerts_v2: a Defender for Endpoint alert whose process evidence has the "
    "implant as parent, resolved when blocked, next to an unrelated alert",
)


def message_evidence(at: datetime, email: dict, blocked: bool) -> dict:
    """The analyzedMessageEvidence Defender for Office 365 attaches to an email alert."""
    sender = email.get("from") or "sender@staticfire.test"
    urls = email.get("urls") or []
    return _evidence(
        "analyzedMessageEvidence",
        at,
        "prevented" if blocked else "detected",
        networkMessageId="c1f0e8a2-5b7d-4e3a-9f2c-08dd1a2b3c4d",
        internetMessageId=email.get("message_id") or "<staticfire@staticfire.test>",
        subject=email.get("subject"),
        receivedDateTime=_iso(at),
        recipientEmailAddress=(email.get("to") or "user@staticfire.test"),
        senderIp="198.51.100.25",
        p1Sender={
            "emailAddress": sender,
            "displayName": "staticfire",
            "domainName": sender.split("@")[-1],
        },
        p2Sender={
            "emailAddress": sender,
            "displayName": "staticfire",
            "domainName": sender.split("@")[-1],
        },
        antiSpamDirection="inbound",
        deliveryAction="blocked" if blocked else "delivered",
        deliveryLocation="quarantine" if blocked else "inbox",
        language="en",
        threats=["Phish"],
        threatDetectionMethods=["urlDetonationReputation"],
        urls=urls,
        urlCount=len(urls),
        attachmentsCount=0,
    )


def _defender_o365_rules(s: Signals, verdict: str) -> list[Rule]:
    source = "microsoftDefenderForOffice365"
    other = {
        "from": "billing@invoices-portal.example",
        "to": "finance@staticfire.test",
        "subject": "Overdue invoice 4471",
        "urls": ["https://invoices-portal.example/view?id=4471"],
        "message_id": "<4471.invoice@invoices-portal.example>",
    }
    alerts = [
        graph_alert(
            "fa638650223344556677_-554433221",
            source,
            "Email messages containing malicious URL removed after delivery",
            s.end,
            "new",
            [message_evidence(s.end, other, False)],
        )
    ]
    if verdict != "none":
        blocked = verdict == "prevented"
        alerts.insert(
            0,
            graph_alert(
                "fa638650998877665544_1122334455",
                source,
                "Email messages containing malicious URL",
                s.end,
                "resolved" if blocked else "new",
                [message_evidence(s.end, s.email, blocked)],
            ),
        )
    for alert in alerts:
        alert["productName"] = "Microsoft Defender for Office 365"
        alert["category"] = "InitialAccess"
        alert["mitreTechniques"] = ["T1566.002"]
    body = {
        "@odata.context": "https://graph.microsoft.com/v1.0/$metadata#security/alerts_v2",
        "value": alerts,
    }
    return [Rule(MS_GRAPH_ALERTS, body, method="GET")]


MICROSOFT_DEFENDER_O365 = VendorCollector(
    recipe="microsoft-defender-o365",
    collector="microsoft-defender-o365",
    env=_ms_env("SOURCE_"),
    rules=_defender_o365_rules,
    # It has no retry window: an expectation it cannot match is answered negative at once
    expected={
        "prevented": {"DETECTION": "Detected", "PREVENTION": "Prevented"},
        "detected": {"DETECTION": "Detected", "PREVENTION": "Not Prevented"},
        "none": {"DETECTION": "Not Detected", "PREVENTION": "Not Prevented"},
    },
    calls=[ms_token_path(), MS_GRAPH_ALERTS],
    proxy=True,
    email=True,
    description="Graph alerts_v2: a Defender for Office 365 alert on the delivered email (sender, "
    "recipient, its URLs, one carrying the implant), blocked and resolved when prevented",
)


# -- Microsoft Sentinel (Log Analytics SecurityAlert, chained after an EDR collector) --
# It matches an expectation an EDR collector already answered with an alertId in its result
# metadata, when a Sentinel alert's link holds that id: what Sentinel's EDR data connectors
# ingest. The fake EDR alert ids are the ones the EDR specs above script.

SENTINEL_WORKSPACE = "9e3b7c1a-4f2d-4a6b-8c0e-5d1f2a3b4c6e"
SENTINEL_QUERY = f"/microsoft-sentinel/v1/workspaces/{SENTINEL_WORKSPACE}/query"
SENTINEL_COLUMNS = [
    ("TenantId", "string"),
    ("TimeGenerated", "datetime"),
    ("DisplayName", "string"),
    ("AlertName", "string"),
    ("AlertSeverity", "string"),
    ("Description", "string"),
    ("ProviderName", "string"),
    ("VendorName", "string"),
    ("VendorOriginalId", "string"),
    ("SystemAlertId", "string"),
    ("ResourceId", "string"),
    ("SourceComputerId", "string"),
    ("AlertType", "string"),
    ("ConfidenceLevel", "string"),
    ("ConfidenceScore", "real"),
    ("IsIncident", "bool"),
    ("StartTime", "datetime"),
    ("EndTime", "datetime"),
    ("ProcessingEndTime", "datetime"),
    ("RemediationSteps", "string"),
    ("ExtendedProperties", "string"),
    ("Entities", "string"),
    ("SourceSystem", "string"),
    ("WorkspaceSubscriptionId", "string"),
    ("WorkspaceResourceGroup", "string"),
    ("ExtendedLinks", "string"),
    ("ProductName", "string"),
    ("ProductComponentName", "string"),
    ("AlertLink", "string"),
    ("Status", "string"),
    ("CompromisedEntity", "string"),
    ("Tactics", "string"),
    ("Techniques", "string"),
    ("SubTechniques", "string"),
    ("Type", "string"),
]


def _log_date(moment: datetime, offset_s: float = 0) -> str:
    return _iso(moment, offset_s).replace("Z", "0000Z")


def _sentinel_alert(s: Signals, verdict: str) -> dict:
    """A SecurityAlert row as the EDR's Sentinel data connector writes it."""
    blocked = verdict == "prevented"
    if s.edr == "crowdstrike":
        vendor_id = "staticfire-1"  # the alert entity of _crowdstrike_rules
        provider, vendor, product = "CrowdStrike", "CrowdStrike", "CrowdStrike Falcon"
        link = f"https://falcon.crowdstrike.com/activity-v2/detections/cid:ind:{vendor_id}"
        name = "Process blocked by Falcon prevention" if blocked else "Suspicious process"
    else:
        vendor_id = "da638650998877665544_1122334455"  # the alert of _defender_rules
        provider, vendor, product = (
            "MDATP",
            "Microsoft",
            "Microsoft Defender Advanced Threat Protection",
        )
        link = f"https://security.microsoft.com/alerts/{vendor_id}?tid={MS_TENANT}"
        name = "Suspicious process was prevented" if blocked else "Suspicious process launched"
    entities = [
        {"$id": "2", "HostName": s.hostname, "OSFamily": "Linux", "Type": "host"},
        {"$id": "3", "Address": s.ipv4, "Type": "ip"},
        {"$id": "4", "ProcessId": "48190", "CommandLine": s.implant, "Type": "process"},
    ]
    return {
        "TenantId": MS_TENANT,
        "TimeGenerated": _log_date(s.end, 60),
        "DisplayName": f"{name} on {s.hostname}",
        "AlertName": name,
        "AlertSeverity": "High",
        "Description": f"{name}: {s.implant}",
        "ProviderName": provider,
        "VendorName": vendor,
        "VendorOriginalId": vendor_id,
        "SystemAlertId": "8c2d4f6a-1b3e-4d5f-9a7c-0e2b4d6f8a1c",
        "ResourceId": "",
        "SourceComputerId": "",
        "AlertType": "EDR",
        "ConfidenceLevel": "Unknown",
        "ConfidenceScore": None,
        "IsIncident": False,
        "StartTime": _log_date(s.end),
        "EndTime": _log_date(s.end, 5),
        "ProcessingEndTime": _log_date(s.end, 60),
        "RemediationSteps": "[]",
        "ExtendedProperties": json.dumps({"Alert Link": link}),
        "Entities": json.dumps(entities),
        "SourceSystem": "Detection",
        "WorkspaceSubscriptionId": "1a2b3c4d-5e6f-4a8b-9c0d-1e2f3a4b5c6d",
        "WorkspaceResourceGroup": "rg-staticfire",
        "ExtendedLinks": json.dumps([{"Href": link, "Category": "Alert", "Label": "Alert"}]),
        "ProductName": product,
        "ProductComponentName": "",
        "AlertLink": link,
        "Status": "Resolved" if blocked else "New",
        "CompromisedEntity": s.hostname,
        "Tactics": "Execution",
        "Techniques": '["T1059"]',
        "SubTechniques": "[]",
        "Type": "SecurityAlert",
    }


def _sentinel_rules(s: Signals, verdict: str) -> list[Rule]:
    unrelated = _sentinel_alert(s, "detected") | {
        "SystemAlertId": "1f3e5d7c-9b2a-4c6e-8d0f-2a4c6e8f0b1d",
        "VendorOriginalId": "da638650000011112222_9988776655",
        "AlertLink": "https://security.microsoft.com/alerts/da638650000011112222_9988776655",
        "DisplayName": "Suspicious sign-in activity",
        "AlertName": "Suspicious sign-in activity",
        "CompromisedEntity": "fin-laptop-07",
    }
    alerts = [unrelated] + ([_sentinel_alert(s, verdict)] if verdict != "none" else [])
    columns = [{"name": name, "type": kind} for name, kind in SENTINEL_COLUMNS]
    rows = [[alert[name] for name, _ in SENTINEL_COLUMNS] for alert in alerts]
    body = {"tables": [{"name": "PrimaryResult", "columns": columns, "rows": rows}]}
    return [Rule(SENTINEL_QUERY, body, method="POST")]


def _sentinel_env(edr_collector: str) -> Callable[[Ofapi], dict[str, str]]:
    def env(fake: Ofapi) -> dict[str, str]:
        from staticfire import recipes, runner

        edr_id = runner.detect(recipes.checkout("collectors", edr_collector), "collector")
        return _ms_env(
            "COLLECTOR_MICROSOFT_SENTINEL_",
            COLLECTOR_MICROSOFT_SENTINEL_SUBSCRIPTION_ID="1a2b3c4d-5e6f-4a8b-9c0d-1e2f3a4b5c6d",
            COLLECTOR_MICROSOFT_SENTINEL_WORKSPACE_ID=SENTINEL_WORKSPACE,
            COLLECTOR_MICROSOFT_SENTINEL_RESOURCE_GROUP="rg-staticfire",
            COLLECTOR_MICROSOFT_SENTINEL_EDR_COLLECTORS=edr_id.component_id,
        )(fake)

    return env


# Sentinel answers prevention only from an alert whose name says it was blocked; it fails an
# expectation only once it is 45 minutes old
SENTINEL_EXPECTED = DETECT_AND_PREVENT

MICROSOFT_SENTINEL = VendorCollector(
    recipe="microsoft-sentinel",
    collector="microsoft-sentinel",
    env=_sentinel_env("crowdstrike"),
    rules=_sentinel_rules,
    expected=SENTINEL_EXPECTED,
    calls=[ms_token_path(), SENTINEL_QUERY],
    proxy=True,
    edr="crowdstrike",
    description="after the crowdstrike collector answered: a SecurityAlert from the Falcon data "
    "connector whose link holds the Falcon alert id, named 'blocked' when prevented",
)

MICROSOFT_SENTINEL_DEFENDER = VendorCollector(
    recipe="microsoft-sentinel-defender",
    collector="microsoft-sentinel",
    env=_sentinel_env("microsoft-defender"),
    rules=_sentinel_rules,
    expected=SENTINEL_EXPECTED,
    calls=[ms_token_path(), SENTINEL_QUERY],
    proxy=True,
    edr="microsoft-defender",
    description="after the microsoft-defender collector answered (the pairing its README "
    "documents): a SecurityAlert from the Defender connector linking the Defender alert",
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
        MICROSOFT_DEFENDER,
        MICROSOFT_DEFENDER_O365,
        MICROSOFT_SENTINEL,
        MICROSOFT_SENTINEL_DEFENDER,
    ]
}
