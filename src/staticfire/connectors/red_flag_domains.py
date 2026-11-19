from staticfire.connector_vendors import ConnectorSpec

SPEC = ConnectorSpec(
    recipe="red-flag-domains",
    connector="external-import/red-flag-domains",
    expected_types={"domain-name", "indicator", "relationship:based-on"},
    calls=["/red-flag-domains/daily/"],
    description="yesterday's daily domain list becomes phishing domain observables and indicators",
)
