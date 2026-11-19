from staticfire.connector_vendors import ConnectorSpec

SPEC = ConnectorSpec(
    recipe="import-file-misp",
    connector="internal-import-file/import-file-misp",
    import_file=("staticfire-misp-event.json", "/fixtures/misp-event.json", "application/json"),
    expected_types={"report", "indicator", "attack-pattern", "intrusion-set"},
    description="a MISP event export becomes a report with indicators and a technique",
)
