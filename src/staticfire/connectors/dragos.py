from staticfire.connector_vendors import ConnectorSpec

SPEC = ConnectorSpec(
    recipe="dragos",
    connector="external-import/dragos",
    env=lambda fake: {
        "DRAGOS_API_TOKEN": "staticfire-fake-token",
        "DRAGOS_API_SECRET": "staticfire-fake-secret",
    },
    expected_types={
        "report",
        "indicator",
        "domain-name",
        "ipv4-addr",
        "url",
        "file",
        "identity",
        "intrusion-set",
        "malware",
        "vulnerability",
        "relationship:based-on",
    },
    calls=["/dragos/api/v1/products", "/dragos/api/v1/indicators", "/dragos/api/v1/products/"],
    description="WorldView reports with their indicators (all types) and tags (sector, group, "
    "malware, CVE); the PDF is uploaded to the report",
)
