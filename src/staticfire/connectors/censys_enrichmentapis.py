from staticfire.connector_vendors import ConnectorSpec
from staticfire.connectors.censys_enrichment import x509_certificate

ENV = {
    # the compose file's nested ${VAR:-${OTHER:-default}} is not a TLP
    "CONNECTOR_MAX_TLP": "TLP:AMBER",
    "CENSYS_ENRICHMENTAPIS_ORGANISATION_ID": "staticfire-org",
    "CENSYS_ENRICHMENTAPIS_TOKEN": "staticfire-fake-key",
}

SPECS = [
    ConnectorSpec(
        recipe="censys-enrichmentapis",
        connector="internal-enrichment/censys-enrichmentapis",
        env=lambda fake: ENV,
        enrich=("IPv4-Addr", "198.51.100.88"),
        expected_types={
            "location",
            "identity",
            "autonomous-system",
            "hostname",
            "software",
            "vulnerability",
            "malware",
            "attack-pattern",
            "note",
            "relationship:located-at",
            "relationship:belongs-to",
            "relationship:resolves-to",
            "relationship:has",
        },
        calls=["/censys-platform/v3/global/asset/enrichment/host/"],
        description="an IPv4 address gets its location, AS, software, CVEs, threats and reputation",
    ),
    ConnectorSpec(
        recipe="censys-enrichmentapis-domain",
        connector="internal-enrichment/censys-enrichmentapis",
        env=lambda fake: ENV,
        enrich=("Domain-Name", "staticfire-censys.example.com"),
        expected_types={"note", "x509-certificate", "relationship:related-to"},
        calls=[
            "/censys-platform/v3/global/asset/webproperty/",
            "/censys-platform/v3/global/search/query",
        ],
        description="a domain gets its web properties (HTTP 404 on one port) and certificates",
    ),
    ConnectorSpec(
        recipe="censys-enrichmentapis-x509",
        connector="internal-enrichment/censys-enrichmentapis",
        env=lambda fake: ENV,
        enrich=x509_certificate,
        expected_types={"x509-certificate"},
        calls=["/censys-platform/v3/global/search/query"],
        description="an X509 certificate is completed from its fingerprint",
    ),
]
