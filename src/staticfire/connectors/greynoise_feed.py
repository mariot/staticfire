from staticfire.connector_vendors import ConnectorSpec

SPEC = ConnectorSpec(
    recipe="greynoise-feed",
    connector="external-import/greynoise-feed",
    env=lambda fake: {
        "GREYNOISE_FEED_API_KEY": "staticfire-fake-key",
        "GREYNOISE_FEED_TYPE": "malicious",
        "GREYNOISE_FEED_LIMIT": "100",
    },
    expected_types={"indicator", "ipv4-addr", "relationship:based-on"},
    calls=["/greynoise/v3/gnql/metadata"],
    description="the GNQL malicious feed (two scroll pages) becomes indicators and observables",
)
