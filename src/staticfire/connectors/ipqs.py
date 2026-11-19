from staticfire.connector_vendors import ConnectorSpec

# One name for both specs: they share the connector's id, and renaming it between two runs
# loses the enrichment message of the run
_ENV = {"IPQS_PRIVATE_KEY": "staticfire-fake-key", "CONNECTOR_NAME": "staticfire ipqs"}

SPECS = [
    ConnectorSpec(
        recipe="ipqs",
        connector="internal-enrichment/ipqs",
        env=lambda fake: _ENV,
        enrich=("IPv4-Addr", "185.220.101.36"),
        expected_types={"autonomous-system", "indicator", "relationship:belongs-to"},
        calls=["/ipqs/api/json/ip"],
        description="a risky address gets its ASN and an indicator labelled with the IPQS verdict",
    ),
    ConnectorSpec(
        recipe="ipqs-domain",
        connector="internal-enrichment/ipqs",
        env=lambda fake: _ENV,
        enrich=("Domain-Name", "staticfire-ipqs.example.com"),
        expected_types={"ipv4-addr", "indicator", "relationship:resolves-to"},
        calls=["/ipqs/api/json/url"],
        description="a malicious domain gets the IP it resolves to and an indicator",
    ),
]
