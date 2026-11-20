from staticfire.connector_vendors import ConnectorSpec

SPEC = ConnectorSpec(
    recipe="spycloud",
    connector="external-import/spycloud",
    env=lambda fake: {
        "SPYCLOUD_API_BASE_URL": "https://api.spycloud.io/enterprise-v2/",
        "SPYCLOUD_API_KEY": "staticfire-fake-key",
        "SPYCLOUD_IMPORT_START_DATE": "P30D",
    },
    expected_types={
        "incident",
        "email-addr",
        "user-account",
        "ipv4-addr",
        "url",
        "domain-name",
        "mac-addr",
        "user-agent",
        "relationship:related-to",
    },
    calls=[
        "/spycloud/enterprise-v2/breach/data/watchlist",
        "/spycloud/enterprise-v2/breach/catalog/",
    ],
    description="paged watchlist breach records (infostealer and plain breach) become "
    "incidents with their observables, titled from the breach catalog",
)
