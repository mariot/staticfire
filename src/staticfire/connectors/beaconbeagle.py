from staticfire.connector_vendors import ConnectorSpec

SPEC = ConnectorSpec(
    recipe="beaconbeagle",
    connector="external-import/beaconbeagle",
    env=lambda fake: {"BEACONBEAGLE_LINK_WATERMARK_TXT": "-licence"},
    expected_types={
        "ipv4-addr",
        "domain-name",
        "indicator",
        "relationship:based-on",
        "url",
        "software",
        "process",
        "text",
        "tool",
        "attack-pattern",
        "location",
        "autonomous-system",
    },
    calls=[
        "/beaconbeagle/api/v1/c2",
        "/beaconbeagle/api/v1/c2/",
        "/beaconbeagle/api/v1/configs/",
    ],
    description="Cobalt Strike C2 servers with their URLs, beacon configs and watermarks",
)
