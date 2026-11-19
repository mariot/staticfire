from staticfire.connector_vendors import ConnectorSpec

SPEC = ConnectorSpec(
    recipe="enisa-euvd",
    connector="external-import/enisa-euvd",
    env=lambda fake: {"ENISA_EUVD_IMPORT_START_DATE": "P30D", "ENISA_EUVD_INGEST_SOFTWARE": "true"},
    expected_types={"vulnerability", "software", "relationship:has"},
    calls=["/enisa-euvd/api/search"],
    description="EUVD search results become vulnerabilities with CVSS/EPSS and affected software",
)
