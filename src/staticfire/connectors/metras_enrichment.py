from staticfire.connector_vendors import ConnectorSpec

ENV = {"METRAS_API_KEY": "staticfire-fake-key"}

SPECS = [
    ConnectorSpec(
        recipe="metras-enrichment",
        connector="internal-enrichment/metras-enrichment",
        env=lambda fake: ENV,
        enrich=("IPv4-Addr", "10.20.30.41"),
        expected_types={"note", "identity", "relationship:related-to"},
        calls=["/metras/api/v1/edr/alerts", "/metras/api/v1/endpoints"],
        description="an internal address gets fleet alerts (note) and its endpoint (system)",
    ),
    ConnectorSpec(
        recipe="metras-enrichment-file",
        connector="internal-enrichment/metras-enrichment",
        env=lambda fake: ENV,
        enrich=("StixFile", "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"),
        expected_types={"note", "identity", "relationship:related-to"},
        calls=["/metras/api/v1/edr/binary/list"],
        description="a file hash gets its binary inventory (note) and first endpoint (system)",
    ),
]
