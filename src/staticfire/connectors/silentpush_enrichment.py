from staticfire.connector_vendors import ConnectorSpec

SPEC = ConnectorSpec(
    recipe="silentpush-enrichment",
    connector="internal-enrichment/silentpush-enrichment",
    env=lambda fake: {"SILENTPUSH_API_KEY": "staticfire-fake-key"},
    enrich=("IPv4-Addr", "93.184.216.34"),
    expected_types={"ipv4-addr", "autonomous-system", "location", "hostname", "x509-certificate"},
    calls=["/silentpush/api/v2/enrich/ipv4/"],
    description="an IPv4 gets its ASN, country, subnet, PTR hostname, certificate and favicon "
    "from the IP enrichment, plus risk labels",
)
