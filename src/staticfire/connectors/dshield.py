from staticfire.connector_vendors import ConnectorSpec

SPEC = ConnectorSpec(
    recipe="dshield",
    connector="external-import/dshield",
    expected_types={"indicator"},
    calls=["/dshield/block.txt"],
    description="the recommended block list (tab separated subnets) becomes IPv4 indicators",
)
