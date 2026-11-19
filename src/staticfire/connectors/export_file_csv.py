from staticfire.connector_vendors import ConnectorSpec

SPEC = ConnectorSpec(
    recipe="export-file-csv",
    connector="internal-export-file/export-file-csv",
    export=("text/csv", "list"),
    description="a list export of an indicator to text/csv",
)
