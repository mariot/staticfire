from staticfire.connector_vendors import ConnectorSpec

SPEC = ConnectorSpec(
    recipe="domaintools-iris-detect",
    connector="external-import/domaintools-iris-detect",
    env=lambda fake: {
        "DOMAINTOOLS_API_KEY": "staticfire-fake-key",
        "DOMAINTOOLS_STORE_IRIS_DATA": "true",
    },
    expected_types={"domain-name", "ipv4-addr", "relationship:resolves-to", "note"},
    calls=["/domaintools/v1/iris-detect/monitors", "/domaintools/v1/iris-detect/domains/new"],
    description="monitored look-alike domains with their IPs, MX and name servers and a note",
)
