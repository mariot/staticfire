from staticfire.connector_vendors import ConnectorSpec

SPEC = ConnectorSpec(
    recipe="urlscan",
    connector="external-import/urlscan",
    env=lambda fake: {"URLSCAN_API_KEY": "staticfire-fake-key"},
    expected_types={"url", "domain-name", "indicator", "relationship:based-on"},
    calls=["/urlscan/api/v1/pro/phishfeed"],
    description="the phishfeed URLs become URL and domain observables and indicators",
)
