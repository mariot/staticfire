from staticfire.connector_vendors import ConnectorSpec

SPEC = ConnectorSpec(
    recipe="ibm-xti",
    connector="external-import/ibm-xti",
    env=lambda fake: {
        "IBM_XTI_TAXII_SERVER_URL": "https://taxii.xforce.ibmcloud.com/taxii2/",
        "IBM_XTI_TAXII_USER": "staticfire",
        "IBM_XTI_TAXII_PASS": "staticfire-fake-key",
        "IBM_XTI_CREATE_OBSERVABLES": "true",
    },
    expected_types={
        "report",
        "malware",
        "threat-actor",
        "indicator",
        "vulnerability",
        "relationship:uses",
    },
    calls=["/ibm-xti/taxii2/api/collections/"],
    description="TAXII 2.1 reports, indicators and vulnerabilities, paged (the platform creates "
    "the observables behind the indicators)",
)
