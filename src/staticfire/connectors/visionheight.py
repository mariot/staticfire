from staticfire.connector_vendors import ConnectorSpec

API = {"VISIONHEIGHT_API_KEY": "staticfire-fake-key"}

SPECS = [
    ConnectorSpec(
        recipe="visionheight",
        connector="internal-enrichment/visionheight",
        env=lambda fake: API,
        enrich=("IPv4-Addr", "185.220.101.34"),
        expected_types={
            "autonomous-system",
            "location",
            "vulnerability",
            "note",
            "indicator",
            "relationship:based-on",
        },
        calls=["/visionheight/ip/"],
        description="a high risk address gets score, labels, ASN, country, CVEs, a context "
        "note and an indicator",
    ),
    ConnectorSpec(
        recipe="visionheight-domain",
        connector="internal-enrichment/visionheight",
        env=lambda fake: API,
        enrich=("Domain-Name", "staticfire-phish.example.org"),
        expected_types={
            "ipv4-addr",
            "x509-certificate",
            "note",
            "indicator",
            "relationship:resolves-to",
            "relationship:based-on",
        },
        calls=["/visionheight/domain/"],
        description="a high risk domain gets its A records, certificates, WHOIS note and indicator",
    ),
]
