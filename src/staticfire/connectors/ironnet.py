from staticfire.connector_vendors import ConnectorSpec

SPEC = ConnectorSpec(
    recipe="ironnet",
    connector="external-import/ironnet",
    env=lambda fake: {"IRONNET_API_KEY": "staticfire-fake-key"},
    expected_types={
        "ipv4-addr",
        "ipv6-addr",
        "domain-name",
        "indicator",
        "malware",
        "relationship:based-on",
        "relationship:communicates-with",
        "relationship:indicates",
    },
    calls=["/ironnet/prod/all/1d/json"],
    description="the daily feed becomes observables, indicators and malware families",
)
