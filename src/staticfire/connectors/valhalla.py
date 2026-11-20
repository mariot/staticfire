from staticfire.connector_vendors import ConnectorSpec

SPEC = ConnectorSpec(
    recipe="valhalla",
    connector="external-import/valhalla",
    env=lambda fake: {"VALHALLA_API_KEY": "staticfire-fake-key"},
    expected_types={"identity", "indicator", "relationship:indicates"},
    calls=["/valhalla/api/v1/status", "/valhalla/api/v1/get", "/github/mitre/cti/master/"],
    description="the YARA rule set becomes YARA indicators related to ATT&CK techniques and groups",
)
