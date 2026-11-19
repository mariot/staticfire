from staticfire.connector_vendors import ConnectorSpec

SPEC = ConnectorSpec(
    recipe="nti",
    connector="external-import/nti",
    env=lambda fake: {"NTI_API_KEY": "staticfire-fake-key"},
    expected_types={
        "indicator",
        "ipv4-addr",
        "ipv6-addr",
        "domain-name",
        "url",
        "file",
        "location",
        "autonomous-system",
        "relationship:based-on",
        "relationship:located-at",
        "relationship:belongs-to",
        "relationship:resolves-to",
    },
    calls=["/nti/api/v2/download/feed/"],
    min_elements=5,
    description="the zipped feed (IOC, IP, domain, URL and sample files), one work per file",
)
