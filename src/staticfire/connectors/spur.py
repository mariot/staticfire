from staticfire.connector_vendors import ConnectorSpec

SPEC = ConnectorSpec(
    recipe="spur",
    connector="external-import/spur",
    env=lambda fake: {"SPUR_API_KEY": "staticfire-fake-key"},
    expected_types={
        "ipv4-addr",
        "ipv6-addr",
        "autonomous-system",
        "location",
        "indicator",
        "relationship:belongs-to",
        "relationship:located-at",
        "relationship:based-on",
    },
    calls=["/spur/v2/anonymous/feed.json.gz", "/spur/v2/residential/feed.json.gz"],
    description="the anonymous (with risks and tunnels) and residential feeds become scored "
    "address observables with ASN, location and indicators",
)
