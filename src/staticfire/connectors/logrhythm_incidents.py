from staticfire.connector_vendors import ConnectorSpec

SPEC = ConnectorSpec(
    recipe="logrhythm-incidents",
    connector="external-import/logrhythm-incidents",
    env=lambda fake: {
        "LOGRHYTHM_INCIDENTS_API_BASE_URL": "https://logrhythm.staticfire.test:8501",
        "LOGRHYTHM_INCIDENTS_API_TOKEN": "staticfire-fake-token",
    },
    expected_types={"incident", "case-incident"},
    calls=["/logrhythm/lr-case-api/cases"],
    description="cases become case-incidents referencing their alarms, imported as incidents",
)
