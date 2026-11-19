from staticfire.connector_vendors import ConnectorSpec

SPEC = ConnectorSpec(
    recipe="microsoft-sentinel-incidents",
    connector="external-import/microsoft-sentinel-incidents",
    env=lambda fake: {
        "MICROSOFT_SENTINEL_INCIDENTS_TENANT_ID": "0b9a2c6e-6d1f-4c0e-9a57-3f2f1d7c8e11",
        "MICROSOFT_SENTINEL_INCIDENTS_CLIENT_ID": "5c1d7e2a-33b4-4e0a-8f6d-9a1b2c3d4e5f",
        "MICROSOFT_SENTINEL_INCIDENTS_CLIENT_SECRET": "staticfire-fake-secret",
        "MICROSOFT_SENTINEL_INCIDENTS_SUBSCRIPTION_ID": "6d0b3c1e-2a4f-4b8e-9c7d-1e2f3a4b5c6d",
        "MICROSOFT_SENTINEL_INCIDENTS_WORKSPACE_ID": "9f8e7d6c-5b4a-4c3d-8e2f-1a0b9c8d7e6f",
        "MICROSOFT_SENTINEL_INCIDENTS_IMPORT_START_DATE": "P3D",
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
    calls=["/microsoft-login/", "/microsoft-sentinel/v1/workspaces/"],
    description="Log Analytics SecurityIncident rows and their SecurityAlert entities (host, "
    "account, ip, url, file, process, malware) become incidents, a case incident and observables",
)
