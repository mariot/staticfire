from staticfire.connector_vendors import ConnectorSpec

SPEC = ConnectorSpec(
    recipe="ipinfo",
    connector="internal-enrichment/ipinfo",
    env=lambda fake: {"IPINFO_TOKEN": "staticfire-fake-key"},
    enrich=("IPv4-Addr", "185.220.101.35"),
    expected_types={"location", "autonomous-system", "relationship:located-at"},
    calls=["/ipinfo/"],
    description="an address gets its country, city, AS and privacy labels (VPN, hosting)",
)
