from staticfire.connector_vendors import ConnectorSpec

SPEC = ConnectorSpec(
    recipe="zerofox-alerts",
    connector="external-import/zerofox-alerts",
    env=lambda fake: {
        "ZEROFOX_ALERTS_API_TOKEN": "staticfire-fake-token",
        "ZEROFOX_ALERTS_PAGE_SIZE": "4",
    },
    expected_types={"incident", "threat-actor", "url", "domain-name", "note"},
    calls=["/zerofox/1.0/alerts/"],
    description="brand alerts (two cursor pages) become incidents, actors, URLs and domains",
)
