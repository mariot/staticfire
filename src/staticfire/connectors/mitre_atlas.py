from staticfire.connector_vendors import ConnectorSpec

SPEC = ConnectorSpec(
    recipe="mitre-atlas-cti",
    connector="external-import/mitre-atlas",
    expected_types={
        "attack-pattern",
        "x-mitre-tactic",
        "x-mitre-matrix",
        "course-of-action",
        "relationship:subtechnique-of",
        "relationship:mitigates",
    },
    calls=["/github/mitre-atlas/atlas-navigator-data/"],
    description="the ATLAS STIX bundle: tactics, matrix, techniques, sub-techniques, mitigations",
)
