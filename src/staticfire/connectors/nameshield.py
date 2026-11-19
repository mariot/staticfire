from staticfire.connector_vendors import ConnectorSpec

SPEC = ConnectorSpec(
    recipe="nameshield",
    connector="external-import/nameshield",
    env=lambda fake: {"NAMESHIELD_AUTH_BEARER": "staticfire-fake-key"},
    expected_types={"domain-name", "indicator", "relationship:based-on"},
    calls=["/nameshield/registrar/v1/domains"],
    description="registrar domains (list, then each one's details) become domains and indicators",
)
