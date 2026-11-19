from staticfire.connector_vendors import ConnectorSpec

SPEC = ConnectorSpec(
    recipe="opencti-stream",
    connector="external-import/opencti-stream",
    env=lambda fake: {
        # the source platform is an SSE fake in ofapi, not the test platform: its live stream
        # carries every other test's changes and the connector writes back into the platform
        "CONNECTOR_LIVE_STREAM_OPENCTI_URL": fake.http_url("opencti-stream"),
        "CONNECTOR_LIVE_STREAM_OPENCTI_TOKEN": "staticfire-fake-key",
    },
    # the SSE connection is not an HTTP(S) request the proxy could relay
    proxy=False,
    expected_types={"identity", "malware", "indicator", "domain-name", "relationship:indicates"},
    # (no `calls`: ofapi journals a streaming response when its connection closes)
    # bundles are sent without a work: the only work is the one of the SSE session
    min_elements=0,
    description="a source platform's live stream (SSE fake) is replicated as one-object bundles",
)
