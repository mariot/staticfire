from staticfire.connector_vendors import ConnectorSpec

SPEC = ConnectorSpec(
    recipe="dogesec-obstracts",
    connector="external-import/dogesec-obstracts",
    env=lambda fake: {
        "OBSTRACTS_API_KEY": "staticfire-fake-key",
        "OBSTRACTS_FEED_IDS": "a1f6d7c2-0b3e-5d4a-9e7c-3b8a2f1c6d05",
        "OBSTRACTS_INTERVAL_HOURS": "1",
        "OBSTRACTS_DAYS_TO_BACKFILL": "7",
    },
    expected_types={"report", "indicator", "malware", "relationship:indicates"},
    calls=["/dogesec/v1/feeds/"],
    description="the posts of a feed become reports with their extracted intelligence",
)
