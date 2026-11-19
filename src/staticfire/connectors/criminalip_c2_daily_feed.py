from staticfire.connector_vendors import ConnectorSpec

SPEC = ConnectorSpec(
    recipe="criminalip-c2-daily-feed",
    connector="external-import/criminalip-c2-daily-feed",
    env=lambda fake: {
        "CRIMINALIP_CSV_URL": "https://c2-daily-feed.criminalip.staticfire.test",
        "CONNECTOR_TYPE": "EXTERNAL_IMPORT",
    },
    expected_types={"indicator", "ipv4-addr", "relationship:based-on", "relationship:located-at"},
    calls=["/criminalip-c2-feed/"],
    description="the daily C2 CSV becomes indicators, IPv4 observables and their countries",
)
