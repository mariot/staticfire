from staticfire.connector_vendors import ConnectorSpec

SPEC = ConnectorSpec(
    recipe="ismalicious",
    connector="internal-enrichment/ismalicious",
    env=lambda fake: {"ISMALICIOUS_API_KEY": "staticfire-fake-key"},
    enrich=("IPv4-Addr", "185.220.101.37"),
    expected_types={"location", "sighting"},
    calls=["/ismalicious/check"],
    description="a malicious address gets its score, category labels and a country sighting",
)
