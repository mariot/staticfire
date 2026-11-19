from staticfire.connector_vendors import ConnectorSpec

SPEC = ConnectorSpec(
    recipe="ipgeolocation",
    connector="internal-enrichment/ipgeolocation",
    env=lambda fake: {"IPGEOLOCATION_API_KEY": "staticfire-fake-key"},
    enrich=("IPv4-Addr", "185.220.101.34"),
    expected_types={
        "location",
        "autonomous-system",
        "identity",
        "hostname",
        "note",
        "relationship:located-at",
        "relationship:belongs-to",
    },
    calls=["/ipgeolocation/v3/ipgeo"],
    description="an address gets its country, city, AS, organization, hostname, security "
    "labels and a report note",
)
