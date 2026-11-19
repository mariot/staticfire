from staticfire.connector_vendors import ConnectorSpec

SPEC = ConnectorSpec(
    recipe="maltiverse",
    connector="external-import/maltiverse",
    env=lambda fake: {
        "MALTIVERSE_USER": "staticfire@example.com",
        "MALTIVERSE_PASSWD": "staticfire-fake-password",
        "MALTIVERSE_FEEDS": "VdhZV34B4jHUXfKt_gDi",
    },
    expected_types={"indicator"},
    calls=["/maltiverse/taxii2/maltiverse/collections/VdhZV34B4jHUXfKt_gDi/objects/"],
    description="the selected TAXII 2.1 feed collection is fetched and its indicators ingested",
)
