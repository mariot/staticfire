from staticfire.connector_vendors import ConnectorSpec

SPEC = ConnectorSpec(
    recipe="stopforumspam",
    connector="external-import/stopforumspam",
    expected_types={"domain-name"},
    calls=["/stopforumspam/downloads/"],
    description="the toxic domains list becomes scored, labelled domain observables (the "
    "indicators are created by the platform from the observables)",
)
