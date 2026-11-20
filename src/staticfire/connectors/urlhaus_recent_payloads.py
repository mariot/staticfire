from staticfire.connector_vendors import ConnectorSpec

SPEC = ConnectorSpec(
    recipe="urlhaus-recent-payloads",
    connector="external-import/urlhaus-recent-payloads",
    env=lambda fake: {"URLHAUS_RECENT_PAYLOADS_API_KEY": "staticfire-fake-key"},
    expected_types={"artifact"},
    calls=["/urlhaus/v1/payloads/recent/", "/urlhaus/v1/download/"],
    opens_work=False,  # it uploads artifacts through the API and sends no bundle
    description="recent payloads are downloaded and uploaded as labelled artifacts (unknown "
    "type and signature-less ones skipped)",
)
