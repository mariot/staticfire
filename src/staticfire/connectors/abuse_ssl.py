from staticfire.connector_vendors import ConnectorSpec

SPEC = ConnectorSpec(
    recipe="abuse-ssl",
    connector="external-import/abuse-ssl",
    expected_types={"ipv4-addr", "indicator", "relationship:based-on"},
    calls=["/abuse-ssl/blacklist/sslipblacklist.csv"],
    description="the SSLBL CSV blacklist becomes IPv4 observables, indicators and based-on links",
)
