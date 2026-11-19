from staticfire.connector_vendors import ConnectorSpec

SPEC = ConnectorSpec(
    recipe="google-dtm",
    connector="external-import/google-dtm",
    env=lambda fake: {
        "GOOGLE_DTM_API_KEY": "staticfire-fake-key",
        "GOOGLE_DTM_ALERT_SEVERITY": "",
        "GOOGLE_DTM_ALERT_TYPE": "",
    },
    expected_types={
        "incident",
        "channel",
        "user-account",
        "file",
        "email-addr",
        "url",
        "domain-name",
        "relationship:uses",
        "relationship:related-to",
    },
    calls=["/virustotal/api/v3/dtm/alerts"],
    description="DTM alerts of every document type (message, credentials, domain discovery, "
    "paste, web, shop, document) become incidents with channels and related observables",
)
