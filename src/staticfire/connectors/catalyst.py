from staticfire.connector_vendors import ConnectorSpec

SPEC = ConnectorSpec(
    recipe="catalyst",
    connector="external-import/catalyst",
    env=lambda fake: {
        "CATALYST_API_KEY": "staticfire-fake-key",
        "CATALYST_SYNC_DAYS_BACK": "30",
        "CATALYST_CREATE_INDICATORS": "true",
        "CATALYST_CREATE_OBSERVABLES": "true",
    },
    expected_types={
        "report",
        "indicator",
        "ipv4-addr",
        "domain-name",
        "url",
        "email-addr",
        "file",
        "malware",
        "tool",
        "vulnerability",
        "campaign",
        "identity",
        "location",
        "threat-actor",
        "intrusion-set",
        "relationship:based-on",
    },
    calls=[
        "/catalyst/api/posts/member-contents/",
        "/catalyst/api/posts/references/",
        "/catalyst/api/actors/",
    ],
    description="member contents become reports with observables, actors, malware and CVEs",
)
