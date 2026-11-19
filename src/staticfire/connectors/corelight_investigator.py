from staticfire.connector_vendors import ConnectorSpec

SPEC = ConnectorSpec(
    recipe="corelight-investigator",
    connector="external-import/corelight-investigator",
    env=lambda fake: {
        "CORELIGHT_INVESTIGATOR_API_BASE_URL": "https://eu.api.investigator.corelight.com",
        "CORELIGHT_INVESTIGATOR_API_KEY": "staticfire-fake-key",
        "CORELIGHT_INVESTIGATOR_IMPORT_WINDOW_DAYS": "5",
    },
    expected_types={"incident", "ipv4-addr", "ipv6-addr", "relationship:related-to"},
    calls=["/corelight-investigator/api/v1/alerts"],
    description="alerts become incidents linked to their source and destination IP observables",
)
