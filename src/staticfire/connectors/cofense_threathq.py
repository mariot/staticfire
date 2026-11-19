from staticfire.connector_vendors import ConnectorSpec

SPEC = ConnectorSpec(
    recipe="cofense-threathq",
    connector="external-import/cofense-threathq",
    env=lambda fake: {
        "COFENSE_THREATHQ_TOKEN_USER": "staticfire-user",
        "COFENSE_THREATHQ_TOKEN_PASSWORD": "staticfire-fake-key",
        "COFENSE_THREATHQ_IMPORT_START_DATE": "P3D",
        "COFENSE_THREATHQ_API_LEAKY_BUCKET_RATE": "50",
        "COFENSE_THREATHQ_API_LEAKY_BUCKET_CAPACITY": "50",
    },
    expected_types={
        "report",
        "file",
        "url",
        "ipv4-addr",
        "domain-name",
        "email-addr",
        "email-message",
        "identity",
    },
    calls=[
        "/cofense-threathq/apiv1/threat/updates",
        "/cofense-threathq/apiv1/threat/malware/",
        "/cofense-threathq/apiv1/t3/malware/",
    ],
    description="threat updates are fetched with their malware details and PDF, then become "
    "reports with their files, URLs, IPs, domains, emails and sectors",
)
