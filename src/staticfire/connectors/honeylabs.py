from staticfire.connector_vendors import ConnectorSpec

SPEC = ConnectorSpec(
    recipe="honeylabs",
    connector="external-import/honeylabs",
    env=lambda fake: {
        "HONEYLABS_API_KEY": "staticfire-fake-key",
        "HONEYLABS_COLLECTIONS": "attackers,exploiters,cve-probers,malware-infrastructure",
        "HONEYLABS_IMPORT_SINCE": "P2D",
    },
    expected_types={"indicator"},
    calls=["/honeylabs/taxii2/api/collections/"],
    description="TAXII 2.1 honeypot indicators (addresses, malware URLs), two pages per "
    "collection; the platform creates the observables behind them",
)
