from staticfire.connector_vendors import ConnectorSpec

SPEC = ConnectorSpec(
    recipe="export-file-ods",
    connector="internal-export-file/export-file-ods",
    export=("application/vnd.oasis.opendocument.spreadsheet", "list"),
    blocked="needs LibreOffice's Python uno module, only shipped in its Docker image",
    description="a list export of an indicator to an OpenDocument spreadsheet",
)
