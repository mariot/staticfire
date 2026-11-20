from staticfire.connector_vendors import ConnectorSpec

SPECS = [
    ConnectorSpec(
        recipe="xposedornot",
        connector="internal-enrichment/xposedornot",
        env=lambda fake: {"XPOSEDORNOT_UPDATE_SCORE": "true"},
        enrich=("Email-Addr", "staticfire.free@example.com"),
        expected_types={"note", "email-addr"},
        calls=["/xposedornot/v1/breach-analytics"],
        description="the community API (no key): a breach summary note, labels and risk score",
    ),
    ConnectorSpec(
        recipe="xposedornot-plus",
        connector="internal-enrichment/xposedornot",
        env=lambda fake: {"XPOSEDORNOT_API_KEY": "staticfire-fake-key"},
        enrich=("Email-Addr", "staticfire.plus@example.com"),
        expected_types={"note", "email-addr"},
        calls=["/xposedornot/v3/check-email/"],
        description="the Plus API (key set): the detailed check-email answer becomes a note",
    ),
]
