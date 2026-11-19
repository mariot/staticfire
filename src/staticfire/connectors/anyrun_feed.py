from staticfire.connector_vendors import ConnectorSpec

SPEC = ConnectorSpec(
    recipe="anyrun-feed",
    connector="external-import/anyrun-feed",
    env=lambda fake: {"ANYRUN_API_KEY": "staticfire-fake-key", "ANYRUN_FEED_FETCH_DEPTH": "3"},
    expected_types={"identity", "indicator"},
    calls=["/anyrun/v1/feeds/taxii2/api1/collections/"],
    description="the TI Feeds TAXII indicators (domains, IPs, URLs) become scored indicators",
)
