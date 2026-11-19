from staticfire.connector_vendors import ConnectorSpec

SPEC = ConnectorSpec(
    recipe="feedly",
    connector="external-import/feedly",
    env=lambda fake: {
        "FEEDLY_API_KEY": "staticfire-fake-key",
        "FEEDLY_STREAM_IDS": "enterprise/staticfire/category/global.all",
        "FEEDLY_DAYS_TO_BACK_FILL": "3",
        "FEEDLY_ENABLE_RELATIONSHIPS": "true",
    },
    expected_types={
        "report",
        "malware",
        "intrusion-set",
        "indicator",
        "vulnerability",
        "attack-pattern",
        "identity",
        "network-traffic",
        "relationship:indicates",
        "relationship:uses",
        "relationship:originates-from",
    },
    calls=["/feedly-ioc/v3/enterprise/ioc"],
    description="two pages of the enterprise IoC stream become reports with their indicators, "
    "intrusion sets (from threat actors), ip:port network traffic and relationships",
)
