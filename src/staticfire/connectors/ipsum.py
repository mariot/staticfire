from staticfire.connector_vendors import ConnectorSpec

SPEC = ConnectorSpec(
    recipe="ipsum",
    connector="external-import/ipsum",
    expected_types={"ipv4-addr"},
    calls=["/github/stamparm/ipsum/"],
    description="the level 5 list of the ipsum repository becomes IPv4 observables, "
    "private addresses dropped",
)
