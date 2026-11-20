from staticfire.connector_vendors import ConnectorSpec

SPEC = ConnectorSpec(
    recipe="socradar",
    connector="external-import/socradar",
    env=lambda fake: {
        "RADAR_BASE_FEED_URL": "https://platform.socradar.com/api/threat/intelligence/feed_list/",
        "RADAR_SOCRADAR_KEY": "staticfire-fake-key",
        "RADAR_FEED_LISTS": '{"staticfire feed": "00000000-0000-4000-8000-000000000001"}',
    },
    expected_types={"indicator", "identity"},
    calls=["/socradar/api/threat/intelligence/feed_list/"],
    description="a feed list of addresses, domains, URLs and hashes becomes indicators "
    "authored by each maintainer",
)
