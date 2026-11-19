from staticfire.connector_vendors import ConnectorSpec

SPEC = ConnectorSpec(
    recipe="greedybear",
    connector="external-import/greedybear",
    env=lambda fake: {
        "GREEDYBEAR_API_BASE_URL": "https://greedybear.honeynet.org",
        "GREEDYBEAR_API_KEY": "staticfire-fake-key",
        "GREEDYBEAR_DEEP_ENRICH": "true",
    },
    expected_types={
        "ipv4-addr",
        "ipv6-addr",
        "domain-name",
        "location",
        "autonomous-system",
        "indicator",
        "attack-pattern",
        "note",
        "tool",
        "relationship:based-on",
        "relationship:indicates",
        "relationship:located-at",
        "relationship:belongs-to",
    },
    calls=["/greedybear/api/feeds/advanced/", "/greedybear/api/feeds/asn/"],
    description="the authenticated advanced and ASN feeds (with per-IoC deep enrichment) become "
    "observables, locations, ASNs, indicators, ATT&CK patterns and statistics notes",
)
