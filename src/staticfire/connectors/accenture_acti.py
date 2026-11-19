from staticfire.connector_vendors import ConnectorSpec

SPEC = ConnectorSpec(
    recipe="accenture-acti",
    connector="external-import/accenture-acti",
    env=lambda fake: {
        "ACCENTURE_ACTI_USERNAME": "staticfire@example.com",
        "ACCENTURE_ACTI_PASSWORD": "staticfire-Fake-Password-1",
        "ACCENTURE_ACTI_USER_POOL_ID": "eu-west-1_StaticFire",
        "ACCENTURE_ACTI_CLIENT_ID": "staticfire-client-id",
        "ACCENTURE_ACTI_S3_BUCKET_NAME": "staticfire-acti",
        "ACCENTURE_ACTI_S3_BUCKET_REGION": "eu-west-1",
        "ACCENTURE_ACTI_S3_BUCKET_ACCESS_KEY": "AKIASTATICFIREFAKE",
        "ACCENTURE_ACTI_S3_BUCKET_SECRET_KEY": "staticfire-fake-secret-key",
        # one 30-minute window: a single request, a single work
        "ACCENTURE_ACTI_RELATIVE_IMPORT_START_DATE": "PT30M",
    },
    expected_types={"report", "intrusion-set", "malware", "indicator", "location"},
    calls=[
        "/accenture-acti/collections/acti/collections",
        "/accenture-acti/document-images/",
    ],
    description="a Cognito (SRP) login, then ACTI reports with their images from S3 become "
    "reports, intrusion sets, malware, indicators and locations",
)
