from staticfire.connector_vendors import ConnectorSpec

SPEC = ConnectorSpec(
    recipe="flare",
    connector="external-import/flare",
    env=lambda fake: {
        "FLARE_API_KEY": "staticfire-fake-key",
        "FLARE_LOOKBACK_DAYS": "7",
    },
    expected_types={
        "incident",
        "email-addr",
        "user-account",
        "ipv4-addr",
        "ipv6-addr",
        "malware",
        "domain-name",
        "url",
        "relationship:related-to",
    },
    calls=[
        "/flare/tokens/generate",
        "/flare/firework/v4/events/tenant/_search",
        "/flare/firework/v2/activities/",
    ],
    description="two pages of tenant events (stealer log, leak, lookalike domain, ransomleak) "
    "become incidents with their observables",
)
