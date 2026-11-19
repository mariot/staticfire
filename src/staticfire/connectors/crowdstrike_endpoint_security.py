from staticfire.connector_vendors import ConnectorSpec

SPEC = ConnectorSpec(
    recipe="crowdstrike-endpoint-security",
    connector="stream/crowdstrike-endpoint-security",
    env=lambda fake: {
        "CROWDSTRIKE_API_BASE_URL": "https://api.crowdstrike.com",
        "CROWDSTRIKE_CLIENT_ID": "staticfire-client",
        "CROWDSTRIKE_CLIENT_SECRET": "staticfire-secret",
    },
    calls=["/crowdstrike/iocs/entities/indicators/v1"],
    description="indicators created in OpenCTI are searched for, then created as Falcon IOCs",
)
