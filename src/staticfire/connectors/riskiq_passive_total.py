from staticfire.connector_vendors import ConnectorSpec

SPEC = ConnectorSpec(
    recipe="riskiq-passive-total",
    connector="internal-enrichment/riskiq-passive-total",
    env=lambda fake: {
        "RISKIQ_USERNAME": "staticfire@example.com",
        "RISKIQ_API_KEY": "staticfire-fake-key",
        "RISKIQ_MAX_TLP": "TLP:AMBER",
        "CONNECTOR_SCOPE": "IPv4-Addr,Domain-Name",
    },
    enrich=("Domain-Name", "staticfire-riskiq.example.com"),
    expected_types={
        "ipv4-addr",
        "ipv6-addr",
        "email-addr",
        "domain-name",
        "relationship:resolves-to",
        "relationship:related-to",
    },
    calls=["/riskiq/pt/v2/account/quota", "/riskiq/pt/v2/dns/passive"],
    description="passive DNS of a domain: A/AAAA addresses, SOA contact, MX/NS/CNAME names "
    "become observables linked by resolves-to and related-to",
)
