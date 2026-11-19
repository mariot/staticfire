from staticfire.connector_vendors import ConnectorSpec

SPEC = ConnectorSpec(
    recipe="orkl",
    connector="external-import/orkl",
    env=lambda fake: {"ORKL_INGEST_TOOLS": "true", "ORKL_INGEST_ACTOR_ALIASES": "true"},
    expected_types={"report", "intrusion-set", "tool", "relationship:uses"},
    calls=["/orkl/api/v1/library/version", "/orkl/api/v1/library/entries"],
    description="the library is walked on a first run: reports with their archive links, "
    "threat actors as intrusion sets with aliases, their tools and uses relationships",
)
