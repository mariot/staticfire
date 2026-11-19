from staticfire.connector_vendors import ConnectorSpec

SPEC = ConnectorSpec(
    recipe="dogesec-cyberthreatexchange",
    connector="external-import/dogesec-cyberthreatexchange",
    env=lambda fake: {
        "CONNECTOR_AUTO_CREATE_SERVICE_ACCOUNT": "false",
        "CYBERTHREATEXCHANGE_API_KEY": "staticfire-fake-key",
        "CYBERTHREATEXCHANGE_FEED_IDS": "6c3bd0e4-7d5c-5a2e-8f0e-2c1d4f5a9b10",
        "CYBERTHREATEXCHANGE_INTERVAL_HOURS": "1",
    },
    expected_types={"indicator", "malware", "intrusion-set", "relationship:indicates"},
    calls=["/dogesec/v1/subscriptions/", "/dogesec/v1/feeds/"],
    description="the subscribed feed (two cursor pages) sent as bundles of indicators",
)
