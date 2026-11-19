from staticfire.connector_vendors import ConnectorSpec

SPEC = ConnectorSpec(
    recipe="export-file-stix",
    connector="internal-export-file/export-file-stix",
    export=("application/vnd.oasis.stix+json", "list"),
    description="a list export of an indicator to application/vnd.oasis.stix+json",
)
