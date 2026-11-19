from staticfire.connector_vendors import ConnectorSpec

SPEC = ConnectorSpec(
    recipe="disinfox",
    connector="external-import/disinfox",
    env=lambda fake: {
        "DISINFOX_URL": "https://disinfox.staticfire.test/api/stix",
        "DISINFOX_API_KEY": "staticfire-fake-key",
    },
    expected_types={
        "intrusion-set",
        "campaign",
        "attack-pattern",
        "tool",
        "location",
        "relationship:attributed-to",
        "relationship:uses",
    },
    calls=["/disinfox/api/stix"],
    description="the STIX export (actors, campaigns, techniques, tools) is sent as is",
)
