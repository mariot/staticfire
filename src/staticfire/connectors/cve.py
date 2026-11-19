from staticfire.connector_vendors import ConnectorSpec

SPEC = ConnectorSpec(
    recipe="cve",
    connector="external-import/cve",
    env=lambda fake: {
        "CVE_API_KEY": "staticfire-fake-key",
        "CVE_MAX_DATE_RANGE": "7",
        "CVE_IMPORT_SOFTWARE": "true",
    },
    expected_types={"vulnerability", "software", "relationship:has"},
    calls=["/nvd-cve-api/rest/json/cves/2.0", "/nvd-cve-api/rest/json/cpematch/2.0"],
    description="NVD CVEs (CVSS 2/3.1/4.0, SSVC, CWE) become vulnerabilities with software (CPE)",
)
