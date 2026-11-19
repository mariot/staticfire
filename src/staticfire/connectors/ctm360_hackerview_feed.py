from staticfire.connector_vendors import ConnectorSpec

SPEC = ConnectorSpec(
    recipe="ctm360-hackerview-feed",
    connector="external-import/ctm360-hackerview-feed",
    env=lambda fake: {"CTM360_HACKERVIEW_FEED_API_KEY": "staticfire-fake-key"},
    expected_types={
        "vulnerability",
        "identity",
        "note",
        "attack-pattern",
        "software",
        "case-incident",
        "relationship:has",
        "relationship:related-to",
    },
    calls=[
        "/ctm360-hackerview/api/v2/issues",
        "/ctm360-hackerview/api/v2/resolved_issues",
        "/ctm360-hackerview/api/v2/assets/domain",
        "/ctm360-hackerview/api/v2/assets/host",
        "/ctm360-hackerview/api/v2/assets/ip_address",
    ],
    description="attack surface issues, resolved issues and assets become cases, systems and notes",
)
