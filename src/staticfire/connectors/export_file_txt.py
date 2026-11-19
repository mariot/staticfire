from staticfire.connector_vendors import ConnectorSpec

SPEC = ConnectorSpec(
    recipe="export-file-txt",
    connector="internal-export-file/export-file-txt",
    export=("text/plain", "list"),
    description="a list export of an indicator to text/plain",
)
