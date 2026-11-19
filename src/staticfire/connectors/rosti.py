from staticfire.connector_vendors import ConnectorSpec

SPEC = ConnectorSpec(
    recipe="rosti",
    connector="external-import/rosti",
    env=lambda fake: {"ROSTI_API_KEY": "staticfire-fake-key", "ROSTI_IMPORT_SINCE": "P7D"},
    expected_types={
        "report",
        "indicator",
        "file",
        "ipv4-addr",
        "domain-name",
        "url",
        "email-addr",
        "mutex",
        "vulnerability",
        "attack-pattern",
        "course-of-action",
        "intrusion-set",
        "campaign",
        "relationship:based-on",
        "relationship:resolves-to",
    },
    calls=[
        "/rosti/v2/reports",
        "/rosti/v2/reports/",
    ],
    description="reports with paged IOC groups (hashes into one file, domain+ip), YARA rules "
    "with a helper rule, MITRE entries and CVEs",
)
