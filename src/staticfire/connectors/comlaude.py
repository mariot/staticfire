from staticfire.connector_vendors import ConnectorSpec

SPEC = ConnectorSpec(
    recipe="comlaude",
    connector="external-import/comlaude",
    env=lambda fake: {
        "COMLAUDE_USERNAME": "staticfire",
        "COMLAUDE_PASSWORD": "staticfire-fake-key",
        "COMLAUDE_API_KEY": "staticfire-fake-key",
        "COMLAUDE_GROUP_ID": "5f0d1c2e-7a3b-4c9d-8e1f-2a4b6c8d0e1f",
        "COMLAUDE_START_TIME": "2026-01-01T00:00:00Z",
        "COMLAUDE_LABELS": "comlaude,safelist",
    },
    expected_types={"domain-name", "indicator", "relationship:based-on"},
    calls=["/comlaude/api_login", "/comlaude/groups/"],
    description="the paginated domain search becomes domain names, indicators and based-on links",
)
