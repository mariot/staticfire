from staticfire.connector_vendors import ConnectorSpec

SPEC = ConnectorSpec(
    recipe="assetnote-import",
    connector="external-import/assetnote-import",
    env=lambda fake: {
        "ASSETNOTE_IMPORT_API_BASE_URL": "https://acme.assetnotecloud.com",
        "ASSETNOTE_IMPORT_API_KEY": "staticfire-fake-key",
        "ASSETNOTE_IMPORT_FIRST_RUN_RETRIEVAL_DATETIME": "2020-01-01T00:00:00Z",
    },
    expected_types={
        "infrastructure",
        "vulnerability",
        "course-of-action",
        "software",
        "note",
        "case-incident",
        "relationship:has",
        "relationship:mitigates",
        "relationship:hosts",
    },
    calls=["/assetnote/api/v2/graphql"],
    description="assets and exposures (GraphQL) become infrastructure, CVEs and incident cases",
)
