from staticfire.connector_vendors import ConnectorSpec

SPEC = ConnectorSpec(
    recipe="anyrun-task",
    connector="internal-enrichment/anyrun-task",
    env=lambda fake: {"ANYRUN_API_KEY": "staticfire-fake-key"},
    enrich=("Url", "http://malicious.staticfire.example/payload"),
    expected_types={
        "url",
        "indicator",
        "ipv4-addr",
        "relationship:based-on",
        "relationship:related-to",
    },
    calls=["/anyrun/v1/analysis", "/anyrun/report/"],
    timeout=420,
    description="a URL is submitted to the sandbox; its verdict, report and IOCs come back",
)
