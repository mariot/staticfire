from staticfire.connector_vendors import ConnectorSpec

SPECS = [
    ConnectorSpec(
        recipe="hostio",
        connector="internal-enrichment/hostio",
        env=lambda fake: {"HOSTIO_TOKEN": "sfhostio123456"},
        enrich=("IPv4-Addr", "93.184.216.34"),
        expected_types={
            "domain-name",
            "autonomous-system",
            "location",
            "note",
            "relationship:resolves-to",
            "relationship:located-at",
            "relationship:belongs-to",
        },
        calls=["/hostio/api/domains/ip/", "/ipinfo/"],
        description="an address gets its hosted domains (two pages) and its IPinfo details",
    ),
    ConnectorSpec(
        recipe="hostio-domain",
        connector="internal-enrichment/hostio",
        env=lambda fake: {"HOSTIO_TOKEN": "sfhostio123456"},
        enrich=("Domain-Name", "staticfire-hostio.example.com"),
        expected_types={
            "ipv4-addr",
            "ipv6-addr",
            "domain-name",
            "note",
            "relationship:resolves-to",
        },
        calls=["/hostio/api/full/"],
        description="a domain gets its DNS records and resolved addresses from the full report",
    ),
]
