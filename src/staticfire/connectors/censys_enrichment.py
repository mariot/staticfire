import uuid

from staticfire.connector_vendors import ConnectorSpec

ENV = {
    "CENSYS_ENRICHMENT_ORGANISATION_ID": "staticfire-org",
    "CENSYS_ENRICHMENT_TOKEN": "staticfire-fake-key",
}


def x509_certificate(cti) -> str:
    """An X509 certificate observable identified by a SHA-256 fingerprint."""
    fingerprint = uuid.uuid4().hex + uuid.uuid4().hex
    return cti.graphql(
        """mutation ($input: [HashInput]) { stixCyberObservableAdd(
             type: "X509-Certificate", X509Certificate: { hashes: $input }) { id } }""",
        {"input": [{"algorithm": "SHA-256", "hash": fingerprint}]},
    )["stixCyberObservableAdd"]["id"]


SPECS = [
    ConnectorSpec(
        recipe="censys-enrichment",
        connector="internal-enrichment/censys-enrichment",
        env=lambda fake: ENV,
        enrich=("IPv4-Addr", "198.51.100.77"),
        expected_types={
            "location",
            "identity",
            "autonomous-system",
            "hostname",
            "software",
            "x509-certificate",
            "note",
            "relationship:located-at",
            "relationship:belongs-to",
            "relationship:resolves-to",
        },
        calls=["/censys-platform/v3/global/asset/host/"],
        description="an IPv4 address gets its location, AS, hostnames, software and certificates",
    ),
    ConnectorSpec(
        recipe="censys-enrichment-domain",
        connector="internal-enrichment/censys-enrichment",
        env=lambda fake: ENV,
        enrich=("Domain-Name", "staticfire-censys.example.com"),
        expected_types={"ipv4-addr", "hostname", "x509-certificate", "relationship:related-to"},
        calls=["/censys-platform/v3/global/search/query"],
        description="a domain gets the hosts and certificates that carry its name",
    ),
    ConnectorSpec(
        recipe="censys-enrichment-x509",
        connector="internal-enrichment/censys-enrichment",
        env=lambda fake: ENV,
        enrich=x509_certificate,
        expected_types={"x509-certificate"},
        calls=["/censys-platform/v3/global/search/query"],
        description="an X509 certificate is completed from its fingerprint",
    ),
]
