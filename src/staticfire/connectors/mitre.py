from staticfire.connector_vendors import ConnectorSpec

SPEC = ConnectorSpec(
    recipe="mitre",
    connector="external-import/mitre",
    env=lambda fake: {"MITRE_REMOVE_STATEMENT_MARKING": "true"},
    expected_types={
        "attack-pattern",
        "x-mitre-tactic",
        "x-mitre-matrix",
        "intrusion-set",
        "malware",
        "tool",
        "campaign",
        "course-of-action",
        "relationship:uses",
        "relationship:subtechnique-of",
    },
    calls=["/github/mitre-attack/attack-stix-data/", "/github/mitre/cti/"],
    description="ATT&CK Enterprise, Mobile, ICS and CAPEC bundles (revoked objects dropped, "
    "statement markings removed, kill chain phases ordered and versioned)",
)
