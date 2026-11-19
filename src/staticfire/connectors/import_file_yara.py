from staticfire.connector_vendors import ConnectorSpec

SPEC = ConnectorSpec(
    recipe="import-file-yara",
    connector="internal-import-file/import-file-yara",
    import_file=("staticfire-rules.yar", "/fixtures/rules.yar", "text/yara+plain"),
    expected_types={"indicator"},
    description="each YARA rule of the file becomes a YARA indicator",
)
