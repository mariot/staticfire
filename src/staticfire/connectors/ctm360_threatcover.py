from staticfire.connector_vendors import ConnectorSpec

SPEC = ConnectorSpec(
    recipe="ctm360-threatcover",
    connector="external-import/ctm360-threatcover",
    env=lambda fake: {
        "CTM360_THREATCOVER_DISCOVERY_URL": "https://threatcover.ctm360.com/taxii2/",
        "CTM360_THREATCOVER_COLLECTION": "Observables",
        "CTM360_THREATCOVER_TOKEN": "staticfire-fake-key",
    },
    expected_types={
        "indicator",
        "ipv4-addr",
        "domain-name",
        "url",
        "file",
        "relationship:based-on",
    },
    calls=["/ctm360-threatcover/taxii2/", "/ctm360-threatcover/api1/collections/"],
    description="the TAXII 2.1 Observables collection (indicators and observables) is imported",
)
