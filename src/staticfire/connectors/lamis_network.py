from staticfire.connector_vendors import ConnectorSpec

SPEC = ConnectorSpec(
    recipe="lamis-network",
    connector="internal-enrichment/lamis-network",
    env=lambda fake: {"LAMIS_NETWORK_API_KEY": "staticfire-fake-key"},
    enrich=("IPv4-Addr", "203.0.113.171"),
    expected_types={"autonomous-system", "location", "indicator"},
    calls=["/lamis-network/v1/ip/"],
    description="a high-risk address gets its ASN, location, flags and a based-on indicator",
)
