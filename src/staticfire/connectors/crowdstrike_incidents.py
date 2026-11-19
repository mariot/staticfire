from staticfire.connector_vendors import ConnectorSpec

SPEC = ConnectorSpec(
    recipe="crowdstrike-incidents",
    connector="external-import/crowdstrike-incidents",
    env=lambda fake: {
        "CROWDSTRIKE_INCIDENTS_API_BASE_URL": "https://api.crowdstrike.com",
        "CROWDSTRIKE_INCIDENTS_CLIENT_ID": "staticfire-client",
        "CROWDSTRIKE_INCIDENTS_CLIENT_SECRET": "staticfire-secret",
        "CROWDSTRIKE_INCIDENTS_ENRICH_FROM_EVENTS": "true",
    },
    expected_types={
        "incident",
        "hostname",
        "ipv4-addr",
        "user-account",
        "attack-pattern",
        "note",
        "file",
        "relationship:related-to",
        "relationship:uses",
    },
    calls=[
        "/crowdstrike/alerts/combined/alerts/v1",
        "/crowdstrike/humio/api/v1/repositories/search-all/queryjobs",
    ],
    description="NG-SIEM alerts, enriched with their LogScale source event, become incidents",
)
