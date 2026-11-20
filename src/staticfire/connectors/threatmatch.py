from staticfire.connector_vendors import ConnectorSpec

SPEC = ConnectorSpec(
    recipe="threatmatch",
    connector="external-import/threatmatch",
    env=lambda fake: {
        "THREATMATCH_CLIENT_ID": "staticfire-client",
        "THREATMATCH_CLIENT_SECRET": "staticfire-fake-key",
        "THREATMATCH_IMPORT_FROM_DATE": "P3D",
    },
    expected_types={
        "intrusion-set",
        "malware",
        "attack-pattern",
        "indicator",
        "report",
        "relationship:uses",
        "relationship:indicates",
        "relationship:related-to",
    },
    calls=[
        "/threatmatch/api/developers-platform/token",
        "/threatmatch/api/stix/profiles/",
        "/threatmatch/api/stix/alerts/",
        "/threatmatch/api/taxii/objects",
    ],
    description="profiles, alerts (actors mapped to intrusion sets) and TAXII indicators",
)
