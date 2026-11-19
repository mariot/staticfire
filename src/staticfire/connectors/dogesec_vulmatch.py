from staticfire.connector_vendors import ConnectorSpec

SPEC = ConnectorSpec(
    recipe="dogesec-vulmatch",
    connector="external-import/dogesec-vulmatch",
    env=lambda fake: {
        "VULMATCH_API_KEY": "staticfire-fake-key",
        "VULMATCH_SBOM_ONLY": "true",
        "VULMATCH_EPSS_SCORE_MIN": "-1",
        "VULMATCH_DAYS_TO_BACKFILL": "7",
        "VULMATCH_INTERVAL_DAYS": "1",
    },
    expected_types={
        "vulnerability",
        "software",
        "indicator",
        "report",
        "attack-pattern",
        "relationship:has",
    },
    calls=["/dogesec/v1/sbom/", "/dogesec/v1/cve/objects/"],
    description=(
        "CVEs matching the SBOM; the grouping/x-cpes-vulnerable model is rewritten into "
        "software 'has' vulnerability relationships"
    ),
)
