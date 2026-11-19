from staticfire.connector_vendors import ConnectorSpec

SPEC = ConnectorSpec(
    recipe="intel471-darknet",
    connector="external-import/intel471-darknet",
    env=lambda fake: {
        "INTEL471_API_USERNAME": "staticfire@example.com",
        "INTEL471_API_KEY": "fake-key",
        "INTEL471_API_URL": "https://api.intel471.com/v1",
        "CONNECTOR_RUN_EVERY": "1h",
    },
    expected_types={
        "incident",
        "report",
        "threat-actor",
        "identity",
        "channel",
        "media-content",
        "domain-name",
        "ipv4-addr",
        "url",
        "email-addr",
        "vulnerability",
        "relationship:related-to",
        "relationship:targets",
    },
    calls=[
        "/intel471/v1/watcherGroups",
        "/intel471/v1/alerts",
        "/intel471/v1/reports/",
        "/intel471/v1/actors/",
    ],
    description="watcher alerts (forum post, private and instant message, report, spot report, "
    "breach alert, actor, entity) become incidents with their content, actors and indicators",
)
