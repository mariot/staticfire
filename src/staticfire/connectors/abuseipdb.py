from staticfire.connector_vendors import ConnectorSpec

SPEC = ConnectorSpec(
    recipe="abuseipdb",
    connector="internal-enrichment/abuseipdb",
    env=lambda fake: {"ABUSEIPDB_API_KEY": "staticfire-fake-key"},
    enrich=("IPv4-Addr", "198.51.100.23"),
    expected_types={"location", "sighting"},
    calls=["/abuseipdb/api/v2/check"],
    description="a reported address gets its score, category labels and per-country sightings",
)
