"""Vendor collectors: how to fake each vendor so its collector answers real agent expectations.

A spec says how to point the collector at ofapi, which vendor answers to script for a verdict
(built from the signals of the expectations the agent just produced), what the collector must
report to OpenAEV, and which vendor calls it must have made. ``recipes.vendor_collector`` runs
any spec end to end.
"""

from __future__ import annotations

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


SPECS: dict[str, VendorCollector] = {spec.recipe: spec for spec in [CORTEX_XDR]}
