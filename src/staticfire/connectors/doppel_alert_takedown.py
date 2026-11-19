from staticfire.connector_vendors import ConnectorSpec

SPEC = ConnectorSpec(
    recipe="doppel-alert-takedown",
    connector="internal-enrichment/doppel-alert-takedown",
    env=lambda fake: {
        "DOPPEL_ALERT_TAKEDOWN_API_KEY": "staticfire-fake-key",
        "DOPPEL_ALERT_TAKEDOWN_USER_API_KEY": "staticfire-fake-user-key",
    },
    enrich=("Domain-Name", "staticfire-phish-login.example.com"),
    expected_types={"note", "domain-name"},
    calls=["/doppel/v1/alert"],
    description="a suspicious domain gets a Doppel alert, a takedown request and a result note",
)
