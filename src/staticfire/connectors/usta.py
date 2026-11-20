from staticfire.connector_vendors import ConnectorSpec

API = "/usta/api/threat-stream/v4"

SPEC = ConnectorSpec(
    recipe="usta",
    connector="external-import/usta",
    env=lambda fake: {
        "USTA_API_KEY": "staticfire-fake-key",
        "USTA_IMPORT_START_DATE": "P3D",
        "USTA_PAGE_SIZE": "3",
    },
    expected_types={
        "indicator",
        "ipv4-addr",
        "domain-name",
        "url",
        "file",
        "malware",
        "incident",
        "user-account",
        "threat-actor",
        "report",
        "note",
        "relationship:based-on",
        "relationship:indicates",
        "relationship:targets",
    },
    calls=[
        f"{API}/security-intelligence/ioc/malicious-urls",
        f"{API}/security-intelligence/ioc/phishing-sites",
        f"{API}/security-intelligence/ioc/malware-hashes",
        f"{API}/security-intelligence/account-takeover-prevention/compromised-credentials-tickets",
        f"{API}/fraud-intelligence/credit-card-tickets",
        f"{API}/deep-sight-tickets",
        "/usta/attachments/",
    ],
    description="the six USTA feeds (two pages each) become IOCs, credential and card "
    "tickets and Deep Sight reports with their PDF",
)
