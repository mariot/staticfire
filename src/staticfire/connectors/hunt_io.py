from staticfire.connector_vendors import ConnectorSpec

SPEC = ConnectorSpec(
    recipe="hunt-io",
    connector="external-import/hunt-io",
    env=lambda fake: {"HUNT_IO_API_KEY": "staticfire-fake-key"},
    expected_types={"ipv4-addr", "indicator"},
    calls=["/hunt-io/"],
    description="the C2 feed (gzip JSON lines) becomes indicators and infrastructure",
)
