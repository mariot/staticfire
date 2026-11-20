from staticfire.connector_vendors import ConnectorSpec

SPEC = ConnectorSpec(
    recipe="zvelo",
    connector="external-import/zvelo",
    env=lambda fake: {
        "ZVELO_CLIENT_ID": "staticfire-client",
        "ZVELO_CLIENT_SECRET": "staticfire-secret",
    },
    expected_types={
        "indicator",
        "url",
        "domain-name",
        "ipv4-addr",
        "ipv6-addr",
        "malware",
        "identity",
        "relationship:based-on",
        "relationship:indicates",
        "relationship:related-to",
    },
    calls=["/zvelo/oauth/token", "/zvelo/v1/threat", "/zvelo/v1/phish", "/zvelo/v1/malicious"],
    description="the threat, phish and malicious collections (two pages each): IOCs, related IPs",
)
