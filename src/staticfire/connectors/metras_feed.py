from staticfire.connector_vendors import ConnectorSpec

SPEC = ConnectorSpec(
    recipe="metras-feed",
    connector="external-import/metras-feed",
    env=lambda fake: {
        "METRAS_API_KEY": "staticfire-fake-key",
        # two pages of alerts and binaries
        "METRAS_PAGE_SIZE": "5",
    },
    expected_types={"incident", "attack-pattern", "url", "file", "identity", "relationship:uses"},
    calls=[
        "/metras/api/v1/edr/alerts",
        "/metras/api/v1/edr/binary/list",
        "/metras/api/v1/endpoints",
    ],
    description="EDR alerts become incidents with techniques, binaries files and endpoints systems",
)
