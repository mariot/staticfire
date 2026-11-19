from staticfire.connector_vendors import ConnectorSpec

SPEC = ConnectorSpec(
    recipe="promptintel",
    connector="external-import/promptintel",
    env=lambda fake: {
        "PROMPTINTEL_API_KEY": "staticfire-fake-key",
        "PROMPTINTEL_IMPORT_START_LIMIT": "50",
        "PROMPTINTEL_IMPORT_LIMIT": "50",
    },
    expected_types={"ai-prompt", "indicator", "identity", "relationship:based-on", "sighting"},
    calls=["/promptintel/api/v1/prompts"],
    description="adversarial prompts become AI-Prompt observables, indicators and Nova rules",
)
