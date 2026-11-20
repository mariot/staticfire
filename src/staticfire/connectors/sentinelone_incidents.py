from datetime import UTC, datetime, timedelta

from staticfire.connector_vendors import ConnectorSpec

SPEC = ConnectorSpec(
    recipe="sentinelone-incidents",
    connector="external-import/sentinelone-incidents",
    env=lambda fake: {
        "SENTINELONE_INCIDENTS_URL": "https://staticfire.sentinelone.net",
        "SENTINELONE_INCIDENTS_API_KEY": "ApiToken staticfire-fake-key",
        "SENTINELONE_INCIDENTS_ACCOUNT_ID": "1000000000000000001",
        "SENTINELONE_INCIDENTS_IMPORT_START_DATE": (datetime.now(UTC) - timedelta(days=3)).strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        ),
    },
    expected_types={
        "incident",
        "indicator",
        "attack-pattern",
        "note",
        "user-account",
        "relationship:uses",
        "relationship:related-to",
    },
    calls=[
        "/sentinelone-console/web/api/v2.1/threats",
        "/sentinelone-console/web/api/v2.1/threats/",
    ],
    description="threats become incidents (one work each) with hash indicators, ATT&CK "
    "patterns, notes and the affected host",
)
