from staticfire.connector_vendors import ConnectorSpec

SPEC = ConnectorSpec(
    recipe="vectra-ai",
    connector="stream/vectra-ai",
    env=lambda fake: {
        "VECTRA_AI_API_BASE_URL": "https://vectra.staticfire.test",
        "VECTRA_AI_API_TOKEN": "staticfire-fake-key",
    },
    calls=["/vectra-ai/api/v2.5/threatFeeds"],
    description="an indicator's domain is uploaded as STIX 1.2 to the connector's own "
    "threat feed, created on first use",
)
