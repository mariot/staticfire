from staticfire.connector_vendors import ConnectorSpec

SPEC = ConnectorSpec(
    recipe="tenable-vuln-management",
    connector="external-import/tenable-vuln-management",
    env=lambda fake: {
        "TENABLE_VULN_MANAGEMENT_API_BASE_URL": "https://cloud.tenable.com",
        "TENABLE_VULN_MANAGEMENT_API_ACCESS_KEY": "staticfire-access-key",
        "TENABLE_VULN_MANAGEMENT_API_SECRET_KEY": "staticfire-fake-key",
        "TENABLE_VULN_MANAGEMENT_EXPORT_SINCE": "2026-11-01T00:00:00+00:00",
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
    calls=[
        "/tenable/vulns/export",
        "/tenable/api/v3/findings/vulnerabilities/host/search",
    ],
    description="a vulnerability export (chunks) joined with the paginated findings ids: "
    "systems, observables, CVEs and affected software",
)
