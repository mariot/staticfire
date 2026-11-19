from datetime import UTC, datetime, timedelta

from staticfire.connector_vendors import ConnectorSpec


def _env(fake) -> dict[str, str]:
    # one day window, starting yesterday: every collection runs once
    start = (datetime.now(UTC) - timedelta(days=2)).date().isoformat()
    return {
        "MANDIANT_API_V4_KEY_ID": "staticfire-fake-key-id",
        "MANDIANT_API_V4_KEY_SECRET": "staticfire-fake-key-secret",
        "MANDIANT_IMPORT_START_DATE": start,
        "MANDIANT_INDICATOR_IMPORT_START_DATE": start,
        "MANDIANT_IMPORT_VULNERABILITIES": "true",
        "MANDIANT_CREATE_NOTES": "true",
    }


SPEC = ConnectorSpec(
    recipe="mandiant",
    connector="external-import/mandiant",
    env=_env,
    expected_types={
        "intrusion-set",
        "malware",
        "campaign",
        "indicator",
        "vulnerability",
        "report",
        "note",
        "attack-pattern",
        "location",
        "identity",
        "relationship:indicates",
        "relationship:uses",
        "relationship:targets",
    },
    calls=[
        "/mandiant/token",
        "/mandiant/v4/actor/",
        "/mandiant/v4/malware/",
        "/mandiant/v4/campaign/",
        "/mandiant/v4/indicator",
        "/mandiant/v4/vulnerability",
        "/mandiant/v4/report/",
    ],
    timeout=480,
    description=(
        "one day window of actors, malware, campaigns, indicators (two pages), "
        "vulnerabilities and reports (STIX bundle, PDF and notes)"
    ),
)
