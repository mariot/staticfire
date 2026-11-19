from staticfire.connector_vendors import ConnectorSpec

SPEC = ConnectorSpec(
    recipe="email-intel-microsoft",
    connector="external-import/email-intel-microsoft",
    env=lambda fake: {
        "EMAIL_INTEL_MICROSOFT_TENANT_ID": "11111111-2222-3333-4444-555555555555",
        "EMAIL_INTEL_MICROSOFT_CLIENT_ID": "66666666-7777-8888-9999-000000000000",
        "EMAIL_INTEL_MICROSOFT_CLIENT_SECRET": "staticfire-fake-secret",
        "EMAIL_INTEL_MICROSOFT_EMAIL": "intel@staticfire-mail.com",
    },
    expected_types={"report"},
    calls=[
        "/microsoft-login/",
        "/microsoft-graph/v1.0/",
    ],
    description="Graph mailbox messages (two pages) become reports; their PDF and CSV "
    "attachments are downloaded one by one and uploaded as files, not in the bundles",
)
