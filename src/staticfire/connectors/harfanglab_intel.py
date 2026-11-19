from staticfire.connector_vendors import ConnectorSpec

SPEC = ConnectorSpec(
    recipe="harfanglab-intel",
    connector="stream/harfanglab-intel",
    env=lambda fake: {
        "HARFANGLAB_INTEL_URL": "https://tenant.hurukai.io",
        "HARFANGLAB_INTEL_TOKEN": "staticfire-fake-key",
        "HARFANGLAB_INTEL_SOURCE_LIST_NAME": "from_OpenCTI",
        "HARFANGLAB_INTEL_RULE_MATURITY": "stable",
    },
    calls=["/harfanglab/api/data/threat_intelligence/IOCRule"],
    description="stream indicators become IOC rules in the HarfangLab source list",
)
