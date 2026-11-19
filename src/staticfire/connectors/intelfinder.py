from staticfire.connector_vendors import ConnectorSpec

SPEC = ConnectorSpec(
    recipe="intelfinder",
    connector="external-import/intelfinder",
    env=lambda fake: {
        # the connector requires a 24 characters key
        "INTELFINDER_TOKEN": "staticfire-fake-key-0001",
        "INTELFINDER_LABELS": "intelfinder",
        "INTELFINDER_MARKING_REFS": "TLP:AMBER",
        "CONNECTOR_RUN_EVERY": "1h",
    },
    expected_types={
        "case-incident",
        "note",
        "task",
        "domain-name",
        "ipv4-addr",
        "ipv6-addr",
        "url",
        "user-account",
    },
    calls=["/intelfinder/api.php"],
    description="alerts become case incidents with a note, a recommendation task and their "
    "domains, addresses, URLs and leaked accounts",
)
