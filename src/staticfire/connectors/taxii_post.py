from staticfire.connector_vendors import ConnectorSpec

COLLECTION = "52892447-4d7e-4f70-b94d-d7f22742ff63"

SPEC = ConnectorSpec(
    recipe="taxii-post",
    connector="stream/taxii-post",
    env=lambda fake: {
        "TAXII_URL": "https://taxii.staticfire.test",
        "TAXII_COLLECTION_ID": COLLECTION,
        "TAXII_LOGIN": "staticfire",
        "TAXII_PASSWORD": "staticfire-fake-key",
    },
    calls=[f"/taxii/root/collections/{COLLECTION}/objects/"],
    description="every stream event is posted to the TAXII 2.1 collection as a one-object bundle",
)
