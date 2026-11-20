from staticfire.connector_vendors import ConnectorSpec

SPEC = ConnectorSpec(
    recipe="trukno",
    connector="external-import/trukno",
    env=lambda fake: {
        "TRUKNO_API_KEY": "staticfire-fake-key",
        "TRUKNO_INITIAL_LOOKBACK": "P2D",
    },
    expected_types={"report", "attack-pattern", "malware"},
    calls=["/trukno/v2/breaches/list", "/trukno/v2/breaches/"],
    description="breaches listed per day (two pages) become reports of TTPs and malware",
)
