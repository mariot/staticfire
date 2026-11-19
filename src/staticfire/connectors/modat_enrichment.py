from staticfire.connector_vendors import ConnectorSpec

SPEC = ConnectorSpec(
    recipe="modat-enrichment",
    connector="internal-enrichment/modat-enrichment",
    env=lambda fake: {
        "MODAT_API_KEY": "staticfire-fake-key",
        "MODAT_INCLUDE_CVES": "true",
    },
    enrich=("IPv4-Addr", "203.0.113.45"),
    expected_types={
        "autonomous-system",
        "location",
        "domain-name",
        "x509-certificate",
        "vulnerability",
        "note",
        "relationship:belongs-to",
        "relationship:resolves-to",
    },
    calls=["/modat/host/"],
    description="a host record becomes ASN, locations, domains, certificate, CVEs and a note",
)
