from staticfire.connector_vendors import ConnectorSpec

SPEC = ConnectorSpec(
    recipe="import-file-stix",
    connector="internal-import-file/import-file-stix",
    import_file=("staticfire-bundle.json", "/fixtures/stix-bundle.json", "application/json"),
    expected_types={"report", "intrusion-set", "malware", "indicator", "relationship:uses"},
    description="a STIX 2.1 bundle (report, intrusion set, malware, indicator) is imported",
)
