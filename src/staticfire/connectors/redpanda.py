from staticfire.connector_vendors import ConnectorSpec

SPEC = ConnectorSpec(
    recipe="redpanda",
    connector="stream/redpanda",
    env=lambda fake: {"REDPANDA_HTTP_PROXY_URL": "https://redpanda.staticfire.test"},
    calls=["/redpanda/topics/opencti"],
    description="every stream event is produced as a JSON record to the topic through the "
    "Redpanda HTTP Proxy (REST, not the Kafka protocol)",
)
