from staticfire.connector_vendors import ConnectorSpec

SPEC = ConnectorSpec(
    recipe="dogesec-stixify",
    connector="external-import/dogesec-stixify",
    env=lambda fake: {
        "CONNECTOR_AUTO_CREATE_SERVICE_ACCOUNT": "false",
        "STIXIFY_API_KEY": "staticfire-fake-key",
        "STIXIFY_DOSSIER_IDS": "3d9e2b7a-5c41-5f8e-b6a0-1e7d4c9f2a38",
        "STIXIFY_INTERVAL_HOURS": "1",
    },
    expected_types={"report", "indicator", "malware", "relationship:indicates"},
    calls=["/dogesec/v1/dossiers/", "/dogesec/v1/reports/"],
    description="the reports of a dossier are sent with the intelligence extracted from them",
)
