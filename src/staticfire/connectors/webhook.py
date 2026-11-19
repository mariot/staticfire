from staticfire.connector_vendors import ConnectorSpec

SPEC = ConnectorSpec(
    recipe="webhook",
    connector="stream/webhook",
    env=lambda fake: {"WEBHOOK_URL": "https://sink.staticfire.test/webhook"},
    calls=["/sink/webhook"],
    description="every stream event is posted to the webhook URL with its token header",
)
