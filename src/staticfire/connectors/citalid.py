from staticfire.connector_vendors import ConnectorSpec

SPEC = ConnectorSpec(
    recipe="citalid",
    connector="external-import/citalid",
    env=lambda fake: {
        "CITALID_CUSTOMER_SUB_DOMAIN_URL": "https://staticfire.citalid.com",
        "CITALID_USER": "staticfire",
        "CITALID_PASSWORD": "staticfire-fake-password",
    },
    expected_types={
        "intrusion-set",
        "malware",
        "vulnerability",
        "indicator",
        "report",
        "relationship:uses",
    },
    calls=["/citalid/facade/risk-intelligence-center/api/v1/stix-bundles/versions/"],
    description="every published version of the risk bundles is downloaded and sent as is",
)
