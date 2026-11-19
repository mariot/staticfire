from staticfire.connector_vendors import ConnectorSpec

SPEC = ConnectorSpec(
    recipe="recorded-future",
    connector="external-import/recorded-future",
    env=lambda fake: {
        "RECORDED_FUTURE_TOKEN": "staticfire-fake-key",
        "RECORDED_FUTURE_PULL_ANALYST_NOTES": "true",
        "RECORDED_FUTURE_PULL_RISK_LIST": "true",
        "RECORDED_FUTURE_PULL_THREAT_MAPS": "true",
        "RECORDED_FUTURE_RISKRULES_AS_LABEL": "true",
        "RECORDED_FUTURE_ANALYST_NOTES_INCLUDE_CONTEXT_ENTITIES": "true",
        "RECORDED_FUTURE_ANALYST_NOTES_GUESS_RELATIONSHIPS": "true",
    },
    expected_types={
        "report",
        "threat-actor",
        "malware",
        "indicator",
        "ipv4-addr",
        "domain-name",
        "url",
        "file",
        "vulnerability",
        "attack-pattern",
        "intrusion-set",
        "relationship:indicates",
        "relationship:based-on",
        "relationship:uses",
        "relationship:targets",
        "location",
        "email-addr",
    },
    calls=[
        "/recorded-future/analyst-note/search",
        "/recorded-future/v2/fusion/files",
        "/recorded-future/threat/maps",
        "/recorded-future/links/search",
    ],
    timeout=420,
    description="analyst notes (with PDF), the five risk lists and the actor and malware threat "
    "maps become reports, indicators, actors, malware and techniques "
    "(alerts and playbook alerts are not exercised)",
)
