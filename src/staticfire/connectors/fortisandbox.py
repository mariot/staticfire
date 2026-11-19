from staticfire.connector_vendors import ConnectorSpec

SHA256 = "b3bf307f507608e833d8c28339fc37f09f6464c2b07c653dabedf827bc0ac794"

SPEC = ConnectorSpec(
    recipe="fortisandbox",
    connector="internal-enrichment/fortisandbox",
    env=lambda fake: {
        "FORTISANDBOX_API_BASE_URL": "https://fortisandbox.staticfire.test",
        "FORTISANDBOX_USERNAME": "staticfire",
        "FORTISANDBOX_PASSWORD": "staticfire-fake-secret",
    },
    enrich=("StixFile", SHA256),
    expected_types={"file", "malware-analysis"},
    calls=["/fortisandbox/jsonrpc"],
    description="a file hash gets its FortiSandbox rating: score, labels and a malware analysis",
)
