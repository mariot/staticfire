from staticfire.connector_vendors import ConnectorSpec

SPEC = ConnectorSpec(
    recipe="rst-whois-api",
    connector="internal-enrichment/rst-whois-api",
    env=lambda fake: {"RST_WHOIS_API_API_KEY": "staticfire-fake-key"},
    enrich=("Domain-Name", "staticfire-whois.example.com"),
    expected_types={"note"},
    calls=["/rstcloud/v1/whois/"],
    description="the WHOIS record of a domain becomes a note attached to it",
)
