from staticfire.connector_vendors import ConnectorSpec

SPEC = ConnectorSpec(
    recipe="swimlane",
    connector="external-import/swimlane",
    env=lambda fake: {
        "SWIMLANE_API_BASE_URL": "https://staticfire.swimlane.app",
        "SWIMLANE_API_TOKEN": "staticfire-fake-key",
        "SWIMLANE_APPLICATION_ID": "a1b2c3d4e5f60718293a4b5c",
    },
    expected_types={"case-incident"},
    calls=["/swimlane/api/app/"],
    description="the records of the application become case-incidents",
)
