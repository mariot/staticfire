from staticfire.connector_vendors import ConnectorSpec

SPEC = ConnectorSpec(
    recipe="montysecurity-c2-tracker",
    connector="external-import/montysecurity-c2-tracker",
    env=lambda fake: {
        "MONTYSECURITY_C2_TRACKER_MALWARE_LIST_URL": (
            "https://c2-tracker.staticfire.test/montysecurity/C2-Tracker/tree/main/data"
        ),
    },
    expected_types={"malware", "ipv4-addr", "ipv6-addr", "relationship:related-to"},
    calls=["/montysecurity-c2-tracker/montysecurity/C2-Tracker/tree/main/data"],
    description=(
        "the data directory page lists the C2 IP files, read from the GitHub raw fake "
        "(montysecurity/C2-Tracker); upstream data is gone, so the old layout is faked"
    ),
)
