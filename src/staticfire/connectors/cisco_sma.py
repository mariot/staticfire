from staticfire.connector_vendors import ConnectorSpec

SPEC = ConnectorSpec(
    recipe="cisco-sma",
    connector="external-import/cisco-sma",
    env=lambda fake: {"CISCO_SMA_API_KEY": "staticfire-fake-key"},
    expected_types={"domain-name", "indicator", "relationship:based-on"},
    calls=["/cisco-sma/api/v3/feeds/"],
    description="the daily Threat Grid domain feeds become domain indicators and observables",
)
