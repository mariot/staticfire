from staticfire.connector_vendors import ConnectorSpec

SPEC = ConnectorSpec(
    recipe="checkfirst-import-connector",
    connector="external-import/checkfirst-import-connector",
    env=lambda fake: {
        "CHECKFIRST_API_URL": "https://api.checkfirst.network",
        "CHECKFIRST_API_KEY": "staticfire-fake-key",
        "CHECKFIRST_SINCE": "P7D",
    },
    expected_types={
        "campaign",
        "intrusion-set",
        "infrastructure",
        "channel",
        "media-content",
        "domain-name",
        "ipv4-addr",
        "url",
        "relationship:publishes",
        "relationship:consists-of",
    },
    calls=["/checkfirst/v1/articles"],
    description="two pages of Pravda network articles become channels, media content, "
    "domains and infrastructure under a campaign",
)
