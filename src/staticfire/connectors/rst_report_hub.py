from datetime import datetime, timedelta

from staticfire.connector_vendors import ConnectorSpec

SPEC = ConnectorSpec(
    recipe="rst-report-hub",
    connector="external-import/rst-report-hub",
    env=lambda fake: {
        "RST_REPORT_HUB_API_KEY": "staticfire-fake-key",
        "RST_REPORT_HUB_IMPORT_START_DATE": (datetime.now() - timedelta(days=1)).strftime("%Y%m%d"),
        "RST_REPORT_HUB_CREATE_OBSERVABLES": "true",
    },
    expected_types={
        "report",
        "indicator",
        "ipv4-addr",
        "domain-name",
        "url",
        "file",
        "email-addr",
        "malware",
        "intrusion-set",
        "attack-pattern",
        "relationship:indicates",
        "relationship:related-to",
        "relationship:uses",
        "relationship:based-on",
    },
    calls=["/rstcloud/v1/reports"],
    description="the reports of a day (STIX bundle plus PDF, attached to the report) with "
    "indicators, threats and techniques, and observables created from the indicators",
)
