from staticfire.connector_vendors import ConnectorSpec

SPEC = ConnectorSpec(
    recipe="malbeacon",
    connector="internal-enrichment/malbeacon",
    env=lambda fake: {"MALBEACON_API_KEY": "staticfire-fake-key"},
    enrich=("IPv4-Addr", "203.0.113.58"),
    expected_types={"indicator", "ipv4-addr", "relationship:based-on", "relationship:related-to"},
    calls=["/malbeacon/v1/c2/c2/"],
    description="a C2 address gets an indicator and the beacon actors' addresses and hostnames",
)
