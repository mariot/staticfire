from staticfire.connector_vendors import ConnectorSpec

SPEC = ConnectorSpec(
    recipe="vmray-platform",
    connector="external-import/vmray-platform",
    env=lambda fake: {
        "VMRAY_API_KEY": "staticfire-fake-key",
        "VMRAY_INITIAL_FETCH_DATE": "2026-01-01",
    },
    expected_types={
        "report",
        "file",
        "indicator",
        "domain-name",
        "url",
        "ipv4-addr",
        "mutex",
        "windows-registry-key",
        "email-addr",
        "process",
        "attack-pattern",
        "location",
        "relationship:based-on",
        "relationship:related-to",
    },
    calls=["/vmray/rest/submission", "/vmray/rest/sample/"],
    description="malicious submissions become reports with their IOCs (files, processes, "
    "domains, URLs, IPs, mutexes, registry keys, e-mails), indicators, ATT&CK patterns "
    "and parent/child links",
)
