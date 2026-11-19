from staticfire.connector_vendors import ConnectorSpec

SPEC = ConnectorSpec(
    recipe="anyrun-lookup",
    connector="internal-enrichment/anyrun-lookup",
    env=lambda fake: {"ANYRUN_API_KEY": "staticfire-fake-key", "ANYRUN_LOOKUP_DEPTH": "30"},
    enrich=("IPv4-Addr", "198.51.100.77"),
    expected_types={
        "indicator",
        "domain-name",
        "url",
        "ipv4-addr",
        "note",
        "relationship:based-on",
        "relationship:related-to",
    },
    calls=["/anyrun/v1/intelligence/api/search"],
    description="a malicious lookup summary adds related observables, indicators and a note",
)
