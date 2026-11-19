from staticfire.connector_vendors import ConnectorSpec

SPEC = ConnectorSpec(
    recipe="netapi",
    connector="internal-enrichment/netapi",
    enrich=("Domain-Name", "staticfire-compromised.xyz"),
    expected_types={"domain-name", "note", "identity"},
    calls=["/netapi/api-json/"],
    description="a listed domain gets the feed label, a reference and a note with its Top 1M rank",
)
