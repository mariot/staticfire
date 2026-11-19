from staticfire.connector_vendors import ConnectorSpec

SPEC = ConnectorSpec(
    recipe="opencti",
    connector="external-import/opencti",
    expected_types={
        "identity",
        "location",
        "marking-definition",
        "relationship:part-of",
        "relationship:located-at",
    },
    description=(
        "the sectors, geography and companies datasets (small STIX bundles) are fetched from "
        "the GitHub raw fake (OpenCTI-Platform/datasets)"
    ),
)
