from staticfire.connector_vendors import ConnectorSpec

SPEC = ConnectorSpec(
    recipe="phishunt",
    connector="external-import/phishunt",
    expected_types={
        "url",
        "indicator",
        "domain-name",
        "ipv4-addr",
        "location",
        "identity",
        "relationship:based-on",
        "relationship:resolves-to",
        "relationship:located-at",
    },
    calls=["/phishunt/feed.json"],
    description="the phishing feed becomes URLs with indicators, domains, resolved addresses, "
    "countries and the hosting companies",
)
