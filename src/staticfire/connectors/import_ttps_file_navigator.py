from staticfire.connector_vendors import ConnectorSpec

SPEC = ConnectorSpec(
    recipe="import-ttps-file-navigator",
    connector="internal-import-file/import-ttps-file-navigator",
    import_file=("staticfire-layer.json", "/fixtures/navigator-layer.json", "application/json"),
    expected_types={"attack-pattern"},
    description="the techniques of an ATT&CK Navigator layer become attack patterns",
)
