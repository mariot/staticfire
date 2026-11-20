from staticfire.connector_vendors import ConnectorSpec

SPEC = ConnectorSpec(
    recipe="threatfox",
    connector="external-import/threatfox",
    env=lambda fake: {"THREATFOX_AUTH_KEY": "staticfire-fake-key"},
    expected_types={
        "indicator",
        "ipv4-addr",
        "domain-name",
        "url",
        "file",
        "malware",
        "relationship:based-on",
        "relationship:indicates",
    },
    calls=["/threatfox/v2/files/exports/"],
    description="the recent IOC CSV export: observables of each type, indicators and "
    "the malware families they indicate",
)
