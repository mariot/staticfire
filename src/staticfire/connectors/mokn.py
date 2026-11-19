from staticfire.connector_vendors import ConnectorSpec

SPEC = ConnectorSpec(
    recipe="mokn",
    connector="external-import/mokn",
    env=lambda fake: {
        "MOKN_CONSOLE_URL": "https://console.mokn.io",
        "MOKN_API_KEY": "staticfire-fake-key",
        "MOKN_FIRST_RUN_DAYS_BACK": "7",
    },
    expected_types={
        "ipv4-addr",
        "indicator",
        "sighting",
        "user-account",
        "incident",
        "relationship:based-on",
    },
    calls=["/mokn/api/v1/baits/logins"],
    description="bait logins (two pages) become IPs, indicators, sightings, accounts, incidents",
)
