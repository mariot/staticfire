from staticfire.connector_vendors import ConnectorSpec

SPEC = ConnectorSpec(
    recipe="fortisiem-incidents",
    connector="external-import/fortisiem-incidents",
    env=lambda fake: {
        "FORTISIEM_INCIDENTS_API_BASE_URL": "https://fortisiem.staticfire.test",
        "FORTISIEM_INCIDENTS_USERNAME": "staticfire",
        "FORTISIEM_INCIDENTS_PASSWORD": "staticfire-fake-secret",
    },
    expected_types={
        "incident",
        "ipv4-addr",
        "ipv6-addr",
        "domain-name",
        "relationship:related-to",
    },
    calls=["/fortisiem/phoenix/rest/pub/incident"],
    description="incidents become STIX incidents related to their address and host observables",
)
