from staticfire.connector_vendors import ConnectorSpec

_ENABLE = {
    "DOPPEL_ENABLE_INCIDENTS": "true",
    "DOPPEL_ENABLE_GROUPING_CASE": "true",
    "DOPPEL_ENABLE_RFT_CASE": "true",
    "DOPPEL_HISTORICAL_POLLING_DAYS": "2",
}

SPECS = [
    ConnectorSpec(
        recipe="doppel",
        connector="external-import/doppel",
        env=lambda fake: {
            "DOPPEL_API_KEY": "staticfire-fake-key",
            "DOPPEL_USER_API_KEY": "staticfire-fake-user-key",
            **_ENABLE,
        },
        expected_types={
            "domain-name",
            "ipv4-addr",
            "url",
            "email-addr",
            "indicator",
            "incident",
            "grouping",
            "case-rft",
            "note",
            "relationship:resolves-to",
            "relationship:based-on",
        },
        calls=["/doppel/v1/alerts"],
        description="brand-abuse alerts become observables, indicators (taken down), incidents, "
        "grouping and takedown (RFT) cases",
    ),
    ConnectorSpec(
        recipe="doppel-v2",
        connector="external-import/doppel",
        env=lambda fake: {
            "DOPPEL_API_VERSION": "v2",
            "DOPPEL_CLIENT_ID": "staticfire",
            "DOPPEL_CLIENT_SECRET": "staticfire-fake-secret",
            **_ENABLE,
        },
        expected_types={"domain-name", "indicator", "incident", "case-rft"},
        calls=["/doppel/oauth/token", "/doppel/v2/alerts"],
        description="the same import through the V2 API: OAuth client credentials, /v2/alerts",
    ),
]
