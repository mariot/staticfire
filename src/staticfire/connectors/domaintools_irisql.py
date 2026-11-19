from staticfire.connector_vendors import ConnectorSpec

SPEC = ConnectorSpec(
    recipe="domaintools-irisql",
    connector="external-import/domaintools-irisql",
    env=lambda fake: {
        "DOMAINTOOLS_API_KEY": "staticfire-fake-key",
        "DOMAINTOOLS_IRIS_QL": "domain contains filigran",
        "DOMAINTOOLS_STORE_IRIS_DATA": "true",
    },
    expected_types={
        "domain-name",
        "ipv4-addr",
        "email-addr",
        "relationship:resolves-to",
        "relationship:related-to",
        "note",
    },
    calls=["/domaintools/v1/iris-investigate"],
    description="an IrisQL query posted to Iris Investigate: domains, IPs, MX/NS, emails, notes",
)
