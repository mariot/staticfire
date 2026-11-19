from staticfire.connector_vendors import ConnectorSpec

SPECS = [
    ConnectorSpec(
        recipe="criminal-ip",
        connector="internal-enrichment/criminal-ip",
        env=lambda fake: {"CRIMINAL_IP_TOKEN": "staticfire-fake-key"},
        enrich=("IPv4-Addr", "198.51.100.77"),
        expected_types={
            "indicator",
            "autonomous-system",
            "location",
            "vulnerability",
            "relationship:based-on",
            "relationship:belongs-to",
            "relationship:located-at",
            "relationship:indicates",
        },
        calls=["/criminal-ip/v1/asset/ip/report", "/criminal-ip/v1/feature/ip/malicious-info"],
        description="an IP report gives a reputation indicator, its AS, city and vulnerabilities",
    ),
    ConnectorSpec(
        recipe="criminal-ip-domain",
        connector="internal-enrichment/criminal-ip",
        env=lambda fake: {"CRIMINAL_IP_TOKEN": "staticfire-fake-key"},
        enrich=("Domain-Name", "staticfire-criminalip.example.com"),
        expected_types={
            "indicator",
            "ipv4-addr",
            "location",
            "relationship:based-on",
            "relationship:resolves-to",
            "relationship:related-to",
        },
        calls=["/criminal-ip/v1/domain/reports", "/criminal-ip/v2/domain/report/"],
        description="a phishing domain scan report gives an indicator, connected IPs and countries",
    ),
]
