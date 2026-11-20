from staticfire.connector_vendors import ConnectorSpec

SPEC = ConnectorSpec(
    recipe="whoisfreaks",
    connector="external-import/whoisfreaks",
    env=lambda fake: {
        "WHOISFREAKS_API_KEY": "staticfire-fake-key",
        "WHOISFREAKS_CREATE_INDICATORS_FOR_NRD": "true",
    },
    expected_types={"domain-name", "indicator", "note", "relationship:based-on", "identity"},
    calls=[
        "/whoisfreaks/v3.4/status",
        "/whoisfreaks/v3.4/stream/threat-feed/",
        "/whoisfreaks/v3.3/stream/domainer/",
    ],
    description="threat feeds and newly registered domains (WHOIS or not): domains, indicators",
)
