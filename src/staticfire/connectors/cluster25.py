from staticfire.connector_vendors import ConnectorSpec

SPEC = ConnectorSpec(
    recipe="cluster25",
    connector="external-import/cluster25",
    env=lambda fake: {
        "CLUSTER25_CLIENT_ID": "staticfire-client",
        "CLUSTER25_CLIENT_SECRET": "staticfire-fake-key",
    },
    expected_types={"indicator", "malware", "relationship:indicates"},
    calls=["/cluster25/api/v1/token", "/cluster25/api/v1/export/indicators"],
    description="the STIX export of indicators of every type becomes indicators related to malware",
)
