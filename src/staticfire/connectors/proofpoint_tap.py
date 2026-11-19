from staticfire.connector_vendors import ConnectorSpec

SPEC = ConnectorSpec(
    recipe="proofpoint-tap",
    connector="external-import/proofpoint-tap",
    env=lambda fake: {
        "PROOFPOINT_TAP_API_PRINCIPAL": "staticfire-principal",
        "PROOFPOINT_TAP_API_SECRET": "staticfire-fake-key",
        "PROOFPOINT_TAP_EXPORT_EVENTS": "true",
        "PROOFPOINT_TAP_EVENTS_TYPE": "all",
        "PROOFPOINT_TAP_API_BACKOFF": "PT1S",
    },
    expected_types={
        "report",
        "intrusion-set",
        "malware",
        "attack-pattern",
        "url",
        "indicator",
        "identity",
        "incident",
        "email-message",
        "email-addr",
        "relationship:uses",
        "relationship:indicates",
        "relationship:related-to",
    },
    calls=["/proofpoint-tap-v2/v2/campaign/ids", "/proofpoint-tap-v2/v2/siem/all"],
    description="campaigns become reports with actors, malware, techniques and URL indicators; "
    "SIEM events become incidents with email messages and addresses",
)
