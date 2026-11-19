from staticfire.connector_vendors import ConnectorSpec

SPEC = ConnectorSpec(
    recipe="google-safebrowsing",
    connector="internal-enrichment/google-safebrowsing",
    env=lambda fake: {"SAFE_BROWSING_API_KEY": "staticfire-fake-key"},
    enrich=("Domain-Name", "malware.staticfire-example.com"),
    expected_types={"domain-name"},
    calls=["/google-safebrowsing/v4/threatMatches:find"],
    description="a flagged domain gets score 100, a Safe Browsing description and a threat-type "
    "label (added through the API, not in the bundle)",
)
