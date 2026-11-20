from staticfire.connector_vendors import ConnectorSpec

ENV = {
    "WHISPER_API_URL": "https://graph.whisper.security",
    "WHISPER_API_KEY": "staticfire-fake-key",
}

SPECS = [
    ConnectorSpec(
        recipe="whisper",
        connector="internal-enrichment/whisper",
        env=lambda fake: ENV,
        enrich=("Domain-Name", "staticfire-whisper.com"),
        expected_types={
            "ipv4-addr",
            "domain-name",
            "identity",
            "note",
            "relationship:resolves-to",
        },
        calls=["/whisper/api/query"],
        description="a domain gets DNS facts, registrar, links, SPF, threat feeds and lookalikes",
    ),
    ConnectorSpec(
        recipe="whisper-ip",
        connector="internal-enrichment/whisper",
        env=lambda fake: ENV,
        enrich=("IPv4-Addr", "93.184.216.34"),
        expected_types={"domain-name", "location", "autonomous-system", "note"},
        calls=["/whisper/api/query"],
        description="an address gets its neighbourhood, threat feed note and announcing ASN",
    ),
]
