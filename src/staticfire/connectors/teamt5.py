from staticfire.connector_vendors import ConnectorSpec

SPEC = ConnectorSpec(
    recipe="teamt5",
    connector="external-import/teamt5",
    env=lambda fake: {
        "TEAMT5_CLIENT_ID": "staticfire-client",
        "TEAMT5_CLIENT_SECRET": "staticfire-fake-key",
        "TEAMT5_API_BASE_URL": "https://api.threatvision.org/",
        "CONNECTOR_SCOPE": "teamt5",
    },
    expected_types={
        "report",
        "intrusion-set",
        "malware",
        "attack-pattern",
        "vulnerability",
        "indicator",
        "ipv4-addr",
        "domain-name",
        "url",
        "relationship:uses",
        "relationship:indicates",
    },
    min_elements=10,
    calls=["/teamt5/oauth/token", "/teamt5/api/v2/reports", "/teamt5/api/v2/ioc_bundles"],
    description="OAuth login, then paginated report and IOC bundle listings, each bundle "
    "downloaded as STIX (the report wraps its bundle in a Report object)",
)
