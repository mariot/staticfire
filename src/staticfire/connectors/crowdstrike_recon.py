from staticfire.connector_vendors import ConnectorSpec

SPEC = ConnectorSpec(
    recipe="crowdstrike-recon",
    connector="external-import/crowdstrike-recon",
    env=lambda fake: {
        "CROWDSTRIKE_RECON_API_BASE_URL": "https://api.crowdstrike.com",
        "CROWDSTRIKE_RECON_CLIENT_ID": "staticfire-client",
        "CROWDSTRIKE_RECON_CLIENT_SECRET": "staticfire-secret",
    },
    expected_types={
        "incident",
        "domain-name",
        "email-addr",
        "user-account",
        "url",
        "malware",
        "relationship:related-to",
    },
    calls=[
        "/crowdstrike/recon/queries/notifications/v1",
        "/crowdstrike/recon/entities/notifications-detailed/v1",
    ],
    description="Recon notifications (typosquatting, exposed data, posts) become incidents",
)
