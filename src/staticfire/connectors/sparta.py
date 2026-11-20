from staticfire.connector_vendors import ConnectorSpec

SPEC = ConnectorSpec(
    recipe="sparta",
    connector="external-import/sparta",
    expected_types={
        "attack-pattern",
        "course-of-action",
        "indicator",
        "identity",
        "relationship:subtechnique-of",
        "relationship:mitigates",
        "relationship:indicates",
    },
    calls=["/sparta/download/STIX"],
    description="the SPARTA STIX bundle is imported; related-to links become subtechnique-of "
    "and mitigates",
)
