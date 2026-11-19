from staticfire.connector_vendors import ConnectorSpec

SPEC = ConnectorSpec(
    recipe="cloudflare-rules-list",
    connector="stream/cloudflare-rules-list",
    env=lambda fake: {
        "CLOUDFLARE_ACCOUNT_ID": "0123456789abcdef0123456789abcdef",
        "CLOUDFLARE_API_TOKEN": "staticfire-fake-key",
        "CLOUDFLARE_LIST_ID": "fedcba9876543210fedcba9876543210",
        "CLOUDFLARE_SYNC_INTERVAL": "PT1S",
    },
    calls=["/cloudflare-rules-list/client/v4/accounts/"],
    description="the IPv4 values of OpenCTI are pushed to a Cloudflare IP list (snapshot "
    "replace, then bulk operation polling)",
)
