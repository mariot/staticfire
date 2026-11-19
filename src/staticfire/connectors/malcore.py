from staticfire.connector_vendors import ConnectorSpec

SPEC = ConnectorSpec(
    recipe="malcore",
    connector="external-import/malcore",
    env=lambda fake: {
        "MALCORE_API_KEY": "staticfire-fake-key",
        # the settings default; the compose file's value lacks the /api/feed path
        "MALCORE_API_URL": "https://api.malcore.io/api/feed",
    },
    expected_types={"file", "indicator", "malware", "relationship:indicates"},
    calls=["/malcore/api/feed"],
    description="the ioc, threat and hash feeds become files, indicators and malware",
)
