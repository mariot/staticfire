from staticfire.connector_vendors import ConnectorSpec

SPEC = ConnectorSpec(
    recipe="wiz-cloud",
    connector="external-import/wiz-cloud",
    env=lambda fake: {
        "WIZ_CLOUD_API_URL": "https://api.us1.app.wiz.io/graphql",
        "WIZ_CLOUD_CLIENT_ID": "staticfire-client",
        "WIZ_CLOUD_CLIENT_SECRET": "staticfire-secret",
        "WIZ_CLOUD_IMPORT_VULNERABILITIES": "true",
        "WIZ_CLOUD_PAGE_SIZE": "2",
    },
    expected_types={
        "incident",
        "attack-pattern",
        "identity",
        "software",
        "user-account",
        "credential",
        "vulnerability",
        "relationship:uses",
        "relationship:targets",
        "relationship:has",
        "relationship:related-to",
    },
    calls=["/wiz/oauth/token", "/wiz/graphql"],
    description="threat detection issues (cursor pages): incidents, techniques, assets and CVEs",
)
