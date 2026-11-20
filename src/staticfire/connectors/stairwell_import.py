from staticfire.connector_vendors import ConnectorSpec

SPEC = ConnectorSpec(
    recipe="stairwell-import",
    connector="external-import/stairwell-import",
    env=lambda fake: {"STAIRWELL_IMPORT_API_TOKEN": "staticfire-fake-key"},
    expected_types={
        "indicator",
        "file",
        "ipv4-addr",
        "domain-name",
        "url",
        "grouping",
        "relationship:based-on",
        "relationship:related-to",
    },
    calls=["/stairwell/v1/objects/metadata"],
    description="two pages of MalEval-malicious files become file indicators (those under the "
    "minimum bucket are dropped) with their network observables, in a per-run grouping",
)
