from staticfire.connector_vendors import ConnectorSpec

SPEC = ConnectorSpec(
    recipe="urlhaus",
    connector="external-import/urlhaus",
    expected_types={"indicator", "url", "relationship:based-on"},
    calls=["/urlhaus/downloads/csv_recent/"],
    description="the recent URLs CSV becomes URL indicators and observables (online and offline)",
)
