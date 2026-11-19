from staticfire.connector_vendors import ConnectorSpec

SPEC = ConnectorSpec(
    recipe="clickhouse",
    connector="stream/clickhouse",
    env=lambda fake: {
        "CLICKHOUSE_BASE_URL": "https://clickhouse.staticfire.test:8443",
        "CLICKHOUSE_PASSWORD": "staticfire-fake-password",
    },
    calls=["/clickhouse/"],
    description="the schema is created, then every stream event is inserted as a JSON row",
)
