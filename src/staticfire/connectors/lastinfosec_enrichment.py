from staticfire.connector_vendors import ConnectorSpec

SPEC = ConnectorSpec(
    recipe="lastinfosec-enrichment",
    connector="internal-enrichment/lastinfosec-enrichment",
    env=lambda fake: {"CONFIG_LIS_APIKEY_CTI": "staticfire-fake-key"},
    enrich=("Domain-Name", "lastinfosec-staticfire.example.net"),
    expected_types={"indicator", "malware", "relationship:indicates"},
    calls=["/lastinfosec/v2/stix21/search/"],
    description="a known domain gets its indicator and the malware it indicates",
)
