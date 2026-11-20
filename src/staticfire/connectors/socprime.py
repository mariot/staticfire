from staticfire.connector_vendors import ConnectorSpec

SPEC = ConnectorSpec(
    recipe="socprime",
    connector="external-import/socprime",
    env=lambda fake: {
        "SOCPRIME_API_KEY": "staticfire-fake-key",
        "SOCPRIME_CONTENT_LIST_NAME": "staticfire list",
        "SOCPRIME_JOB_IDS": "staticfire-job",
        "SOCPRIME_SIEM_TYPE": "splunk",
    },
    expected_types={
        "indicator",
        "attack-pattern",
        "intrusion-set",
        "malware",
        "tool",
        "vulnerability",
        "relationship:indicates",
    },
    calls=["/socprime/v1/content-list", "/socprime/v1/ccm/jobs/", "/socprime/v1/search-sigmas"],
    description="Sigma rules of a content list and a job become indicators linked to the "
    "ATT&CK techniques, tools and groups of mitre/cti and to CVEs; other SIEM types are searched",
)
