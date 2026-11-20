from staticfire.connector_vendors import ConnectorSpec

SPEC = ConnectorSpec(
    recipe="tenable-security-center",
    connector="external-import/tenable-security-center",
    env=lambda fake: {
        "TSC_API_BASE_URL": "https://tsc.staticfire.test",
        "TSC_API_ACCESS_KEY": "staticfire-access-key",
        "TSC_API_SECRET_KEY": "staticfire-fake-key",
        "TSC_SEVERITY_MIN_LEVEL": "low",
    },
    expected_types={
        "vulnerability",
        "identity",
        "ipv4-addr",
        "software",
        "relationship:has",
        "relationship:related-to",
    },
    min_elements=10,
    calls=["/tenable/rest/scanResult", "/tenable/rest/hosts/search", "/tenable/rest/analysis"],
    description="completed scan results lead to the scanned assets, their findings "
    "and the CVE details: systems, observables, CVEs and affected software",
)
