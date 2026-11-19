from datetime import UTC, datetime, timedelta

from staticfire.connector_vendors import ConnectorSpec

SPEC = ConnectorSpec(
    recipe="alienvault",
    connector="external-import/alienvault",
    env=lambda fake: {
        "ALIENVAULT_API_KEY": "staticfire-fake-key",
        "ALIENVAULT_PULSE_START_TIMESTAMP": (datetime.now(UTC) - timedelta(days=3)).strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        ),
    },
    expected_types={
        "report",
        "indicator",
        "ipv4-addr",
        "ipv6-addr",
        "domain-name",
        "url",
        "email-addr",
        "file",
        "vulnerability",
        "intrusion-set",
        "malware",
        "attack-pattern",
        "relationship:indicates",
    },
    calls=["/alienvault/api/v1/pulses/subscribed"],
    description="subscribed OTX pulses become reports with observables, indicators, malware, "
    "CVEs and ATT&CK patterns",
)
