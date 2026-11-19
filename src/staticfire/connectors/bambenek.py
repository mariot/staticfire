from staticfire.connector_vendors import ConnectorSpec

SPEC = ConnectorSpec(
    recipe="bambenek",
    connector="external-import/bambenek",
    env=lambda fake: {
        "BAMBENEK_USERNAME": "staticfire",
        "BAMBENEK_PASSWORD": "staticfire-fake-key",
    },
    expected_types={"indicator", "domain-name", "ipv4-addr", "relationship:based-on"},
    calls=["/bambenek/feeds/dga/"],
    description="the DGA and C2 domain and IP feeds (CSV) become indicators and observables",
)
