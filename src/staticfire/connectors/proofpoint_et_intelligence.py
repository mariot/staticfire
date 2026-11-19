from staticfire.connector_vendors import ConnectorSpec

SPEC = ConnectorSpec(
    recipe="proofpoint-et-intelligence",
    connector="internal-enrichment/proofpoint-et-intelligence",
    env=lambda fake: {
        "PROOFPOINT_ET_INTELLIGENCE_API_KEY": "staticfire-fake-key",
        "CONNECTOR_AUTO": "false",
    },
    enrich=("IPv4-Addr", "185.220.101.57"),
    expected_types={
        "domain-name",
        "file",
        "location",
        "autonomous-system",
        "relationship:resolves-to",
        "relationship:communicates-with",
        "relationship:located-at",
        "relationship:belongs-to",
    },
    calls=[
        "/proofpoint-et/v1/ips/185.220.101.57/reputation",
        "/proofpoint-et/v1/ips/185.220.101.57/domains",
        "/proofpoint-et/v1/ips/185.220.101.57/samples",
        "/proofpoint-et/v1/ips/185.220.101.57/geoloc",
        "/proofpoint-et/v1/ips/185.220.101.57/asn",
    ],
    description="an IP gets its reputation categories, domains, samples, location and ASN",
)
