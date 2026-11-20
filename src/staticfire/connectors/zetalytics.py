from staticfire.connector_vendors import ConnectorSpec

ENV = {
    # the SDK refuses a token that is not 32 characters long
    "ZETALYTICS_TOKEN": "staticfire-fake-token-0000000000",
    "ZETALYTICS_MODE": "deep",
}

SPECS = [
    ConnectorSpec(
        recipe="zetalytics",
        connector="internal-enrichment/zetalytics",
        env=lambda fake: ENV,
        enrich=("Domain-Name", "staticfire-zeta.com"),
        expected_types={
            "domain-name",
            "ipv4-addr",
            "ipv6-addr",
            "note",
            "relationship:resolves-to",
        },
        calls=["/zetalytics/api/v2/domain2rrtypes", "/zetalytics/api/v2/subdomains"],
        description="a domain gets passive and live DNS, subdomains, registration and pivots",
    ),
    ConnectorSpec(
        recipe="zetalytics-ip",
        connector="internal-enrichment/zetalytics",
        env=lambda fake: ENV,
        enrich=("IPv4-Addr", "93.184.216.34"),
        expected_types={"domain-name", "autonomous-system", "location"},
        calls=["/zetalytics/api/v2/ip", "/zetalytics/api/v2/ip2pwhois"],
        description="an address gets the names seen on it, its ASN, prefix and location",
    ),
]
