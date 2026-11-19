from staticfire.connector_vendors import ConnectorSpec

SPEC = ConnectorSpec(
    recipe="google-dns",
    connector="internal-enrichment/google-dns",
    enrich=("Domain-Name", "staticfire-dns.example.org"),
    expected_types={
        "domain-name",
        "ipv4-addr",
        "text",
        "relationship:resolves-to",
        "relationship:related-to",
    },
    calls=["/google-dns/resolve"],
    description="a domain gets its NS, A, CNAME, MX and TXT records from the DNS-over-HTTPS API",
)
