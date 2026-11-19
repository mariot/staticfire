from staticfire.connector_vendors import ConnectorSpec

SPEC = ConnectorSpec(
    recipe="infoblox",
    connector="external-import/infoblox",
    env=lambda fake: {"INFOBLOX_API_KEY": "staticfire-fake-key"},
    expected_types={"ipv4-addr", "domain-name", "url", "indicator", "relationship:based-on"},
    calls=["/infoblox/tide/api/data/threats"],
    description="TIDE threats of the ip, url and host types become observables and indicators",
)
