from datetime import UTC, datetime, timedelta

from staticfire.connector_vendors import ConnectorSpec

SPEC = ConnectorSpec(
    recipe="misp-feed",
    connector="external-import/misp-feed",
    env=lambda fake: {
        "MISP_FEED_URL": "https://feed.misp.staticfire.test",
        "MISP_FEED_IMPORT_FROM_DATE": (datetime.now(UTC) - timedelta(days=7)).strftime("%Y-%m-%d"),
        "MISP_FEED_CREATE_INDICATORS": "true",
        "MISP_FEED_CREATE_OBSERVABLES": "true",
        "MISP_FEED_CREATE_OBJECT_OBSERVABLES": "true",
    },
    expected_types={
        "report",
        "indicator",
        "domain-name",
        "ipv4-addr",
        "intrusion-set",
        "malware",
        "attack-pattern",
        "relationship:indicates",
    },
    calls=["/misp/manifest.json"],
    description="the feed manifest and its event files become reports with indicators, "
    "observables and threat entities",
)
