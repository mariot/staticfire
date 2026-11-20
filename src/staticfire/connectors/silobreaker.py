from staticfire.connector_vendors import ConnectorSpec

SPEC = ConnectorSpec(
    recipe="silobreaker",
    connector="external-import/silobreaker",
    env=lambda fake: {
        "SILOBREAKER_API_KEY": "staticfire-fake-key",
        "SILOBREAKER_API_SHARED": "staticfire-fake-shared-secret",
        "SILOBREAKER_LISTS": "36592",
        "SILOBREAKER_IMPORT_START_DATE": "P3D",
    },
    expected_types={
        "report",
        "intrusion-set",
        "malware",
        "attack-pattern",
        "vulnerability",
        "location",
        "identity",
        "domain-name",
        "ipv4-addr",
        "email-addr",
        "indicator",
        "relationship:targets",
        "relationship:uses",
    },
    calls=["/silobreaker/v2/lists/", "/silobreaker/v2/documents/search"],
    description="a list's documents (report, news, blog) become reports with their related "
    "entities, indicators scored by enrichment and a downloaded PDF attached to the report",
)
