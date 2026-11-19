from staticfire.connector_vendors import ConnectorSpec

SPEC = ConnectorSpec(
    recipe="microsoft-defender-incidents",
    connector="external-import/microsoft-defender-incidents",
    env=lambda fake: {
        "MICROSOFT_DEFENDER_INCIDENTS_TENANT_ID": "0b9a2c6e-6d1f-4c0e-9a57-3f2f1d7c8e11",
        "MICROSOFT_DEFENDER_INCIDENTS_CLIENT_ID": "5c1d7e2a-33b4-4e0a-8f6d-9a1b2c3d4e5f",
        "MICROSOFT_DEFENDER_INCIDENTS_CLIENT_SECRET": "staticfire-fake-secret",
        "MICROSOFT_DEFENDER_INCIDENTS_IMPORT_START_DATE": "P3D",
    },
    expected_types={
        "incident",
        "case-incident",
        "attack-pattern",
        "ipv4-addr",
        "ipv6-addr",
        "url",
        "user-account",
        "file",
        "directory",
        "identity",
        "malware",
        "hostname",
        "relationship:uses",
        "relationship:related-to",
        "relationship:targets",
    },
    calls=["/microsoft-login/", "/microsoft-graph/v1.0/security/incidents"],
    description="Graph security incidents with their alerts and every evidence type become "
    "incidents, a case incident and observables",
)
