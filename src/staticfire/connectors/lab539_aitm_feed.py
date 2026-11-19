from staticfire.connector_vendors import ConnectorSpec

SPEC = ConnectorSpec(
    recipe="lab539-aitm-feed",
    connector="external-import/lab539-aitm-feed",
    env=lambda fake: {"AITM_FEED_API_KEY": "staticfire-fake-key"},
    expected_types={"indicator"},
    calls=["/lab539/v1.0/list"],
    description="AiTM infrastructure records become indicators (OpenCTI creates the observables)",
)
