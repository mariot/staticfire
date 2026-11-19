from staticfire.connector_vendors import ConnectorSpec

ENV = {"HYBRID_ANALYSIS_SANDBOX_TOKEN": "staticfire-fake-key"}
EXPECTED = {
    "malware-analysis",
    "software",
    "attack-pattern",
    "domain-name",
    "ipv4-addr",
    "ipv6-addr",
    "file",
    "relationship:related-to",
    "relationship:drops",
}

SPECS = [
    ConnectorSpec(
        recipe="hybrid-analysis-sandbox",
        connector="internal-enrichment/hybrid-analysis-sandbox",
        env=lambda fake: ENV,
        enrich=(
            "StixFile",
            "5d41402abc4b2a76b9719d911017c5925d41402abc4b2a76b9719d911017c592",
        ),
        expected_types=EXPECTED,
        calls=["/hybrid-analysis/api/v2/search/hash", "/hybrid-analysis/api/v2/report/"],
        description="a file hash found in an existing analysis: TTPs, network, dropped files",
    ),
    ConnectorSpec(
        recipe="hybrid-analysis-sandbox-url",
        connector="internal-enrichment/hybrid-analysis-sandbox",
        env=lambda fake: ENV,
        enrich=("Url", "http://staticfire-sandbox.example.com/payload.exe"),
        expected_types=EXPECTED,
        calls=["/hybrid-analysis/api/v2/submit/url", "/hybrid-analysis/api/v2/report/"],
        description="a URL is submitted to the sandbox and its finished report attached",
    ),
]
