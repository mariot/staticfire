from staticfire.connector_vendors import ConnectorSpec

SPEC = ConnectorSpec(
    recipe="cuckoo",
    connector="external-import/cuckoo",
    env=lambda fake: {
        "CONNECTOR_SCOPE": "cuckoo",
        "CUCKOO_API_URL": "https://cuckoo.staticfire.test/api/",
        "CUCKOO_BASE_URL": "https://cuckoo.staticfire.test/",
        "CUCKOO_CREATE_INDICATORS": "true",
        "CUCKOO_REPORT_SCORE": "7",
    },
    expected_types={
        "report",
        "file",
        "indicator",
        "ipv4-addr",
        "domain-name",
        "process",
        "relationship:related-to",
        "relationship:resolves-to",
    },
    calls=["/cuckoo/api/tasks/list", "/cuckoo/api/tasks/summary/"],
    description="reported sandbox tasks become reports with the sample, network and process data",
)
