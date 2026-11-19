from staticfire.connector_vendors import ConnectorSpec

SPEC = ConnectorSpec(
    recipe="portspoof",
    connector="external-import/portspoof",
    blocked=(
        "no vendor HTTP API to fake: the connector only consumes PortSpoofPro session states from "
        "an AMQP queue (RabbitMQ, exchange portspoof-full-state-updates) published by the vendor's "
        "aggregator, and staticfire has no way to publish to it; it also refuses to start unless "
        "CONNECTOR_ID is a UUIDv4 (synchronizer.py build_config_from_env) while staticfire derives "
        "uuid5 connector ids"
    ),
    description="PortSpoofPro scanner sessions (AMQP) become threat actors and sightings",
)
