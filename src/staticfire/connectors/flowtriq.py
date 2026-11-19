from staticfire.connector_vendors import ConnectorSpec

SPEC = ConnectorSpec(
    recipe="flowtriq",
    connector="external-import/flowtriq",
    env=lambda fake: {"FLOWTRIQ_API_KEY": "staticfire-fake-key"},
    expected_types={"ipv4-addr", "ipv6-addr", "indicator", "relationship:based-on"},
    calls=["/flowtriq/api/v1/incidents"],
    description="DDoS incidents become target and source IP observables with indicators",
)
