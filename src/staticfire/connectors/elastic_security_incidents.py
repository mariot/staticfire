from staticfire.connector_vendors import ConnectorSpec

SPEC = ConnectorSpec(
    recipe="elastic-security-incidents",
    connector="external-import/elastic-security-incidents",
    env=lambda fake: {
        "ELASTIC_SECURITY_URL": "https://elastic-security-es.staticfire.test",
        "ELASTIC_SECURITY_KIBANA_URL": "https://elastic-security-kb.staticfire.test",
        "ELASTIC_SECURITY_API_KEY": "staticfire-fake-key",
    },
    expected_types={
        "incident",
        "note",
        "attack-pattern",
        "ipv4-addr",
        "domain-name",
        "url",
        "file",
        "relationship:related-to",
        "relationship:uses",
        "case-incident",
        "email-addr",
        "hostname",
        "user-account",
    },
    calls=[
        "/elastic-security/_cluster/health",
        "/elastic-security/.alerts-security.alerts-*/_search",
        "/elastic-security/api/cases/_find",
        "/elastic-security/api/cases/case-0001/alerts",
    ],
    description="detection alerts (observables, ATT&CK techniques) become incidents; a Kibana "
    "case with its comments and attached alerts becomes a case-incident",
)
