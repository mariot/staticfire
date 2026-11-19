from staticfire.connector_vendors import ConnectorSpec

_ENV = lambda fake: {  # noqa: E731
    "DOMAINTOOLS_API_USERNAME": "staticfire",
    "DOMAINTOOLS_API_KEY": "staticfire-fake-key",
}

SPECS = [
    ConnectorSpec(
        recipe="domaintools",
        connector="internal-enrichment/domaintools",
        env=_ENV,
        enrich=("Domain-Name", "staticfire-suspect.example.com"),
        expected_types={"ipv4-addr", "email-addr", "autonomous-system", "relationship:resolves-to"},
        calls=["/domaintools/v1/iris-investigate"],
        description="a domain is investigated: its IPs, ASNs, MX/NS hosts and WHOIS/SSL emails",
    ),
    ConnectorSpec(
        recipe="domaintools-ip",
        connector="internal-enrichment/domaintools",
        env=_ENV,
        enrich=("IPv4-Addr", "198.51.100.77"),
        expected_types={"domain-name", "autonomous-system", "relationship:resolves-to"},
        calls=["/domaintools/v1/iris-investigate"],
        description="an address is investigated: the domains seen on it become domain-names",
    ),
]
