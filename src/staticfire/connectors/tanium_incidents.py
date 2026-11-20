from staticfire.connector_vendors import ConnectorSpec

SPEC = ConnectorSpec(
    recipe="tanium-incidents",
    connector="external-import/tanium-incidents",
    env=lambda fake: {
        "TANIUM_INCIDENTS_URL": "https://staticfire-api.cloud.tanium.com",
        "TANIUM_INCIDENTS_URL_CONSOLE": "https://staticfire.cloud.tanium.com",
        "TANIUM_INCIDENTS_TOKEN": "token-staticfire-fake-key",
    },
    expected_types={
        "incident",
        "hostname",
        "ipv4-addr",
        "user-account",
        "file",
        "attack-pattern",
        "relationship:related-to",
        "relationship:uses",
    },
    calls=[
        "/cti-tanium/plugin/products/threat-response/api/v1/alerts",
        "/cti-tanium/plugin/products/threat-response/api/v1/intels/",
    ],
    description="Threat Response alerts (the suppressed one skipped) become incidents with "
    "hostname, address, user, file and MITRE techniques (no sighting: it needs an indicator "
    "carrying the intel document id)",
)
