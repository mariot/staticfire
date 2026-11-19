from staticfire.connector_vendors import ConnectorSpec

SPEC = ConnectorSpec(
    recipe="arcsight-incidents",
    connector="external-import/arcsight-incidents",
    env=lambda fake: {
        "CONNECTOR_SCOPE": "arcsight",
        "ARCSIGHT_INCIDENTS_API_BASE_URL": "https://arcsight.staticfire.test:8443",
        "ARCSIGHT_INCIDENTS_USERNAME": "staticfire",
        "ARCSIGHT_INCIDENTS_PASSWORD": "staticfire-fake-password",
    },
    expected_types={"incident", "case-incident", "identity"},
    calls=[
        "/arcsight/www/manager-service/rest/CaseService/getResourceById",
        "/arcsight/www/manager-service/rest/SecurityEventService/getSecurityEvents",
    ],
    description="ESM cases become case incidents grouping their security events as incidents",
)
