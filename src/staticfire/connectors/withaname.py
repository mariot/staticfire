from staticfire.connector_vendors import ConnectorSpec

SPEC = ConnectorSpec(
    recipe="withaname",
    connector="external-import/withaname",
    env=lambda fake: {"WITHANAME_IMPORT_START_TIMESTAMP": "0"},
    expected_types={"domain-name", "ipv4-addr", "relationship:resolves-to", "note", "identity"},
    calls=["/withaname/api/configs", "/withaname/api/config/"],
    description="every DDoSIA snapshot (two pages) becomes hosts, addresses and target notes",
)
