from staticfire.connector_vendors import ConnectorSpec

_ENV = {"DOMAINTOOLS_API_KEY": "staticfire-fake-key", "DOMAINTOOLS_TOP": "8"}

SPECS = [
    ConnectorSpec(
        recipe="domaintools-feeds",
        connector="external-import/domaintools-feeds",
        env=lambda fake: {**_ENV, "DOMAINTOOLS_FEED_TYPE": "domainhotlist"},
        expected_types={"indicator", "identity"},
        calls=["/domaintools/v1/feed/domainhotlist"],
        description="the Domain Hotlist feed (JSON lines with risk scores) becomes indicators",
    ),
    ConnectorSpec(
        recipe="domaintools-feeds-nod",
        connector="external-import/domaintools-feeds",
        env=lambda fake: {**_ENV, "DOMAINTOOLS_FEED_TYPE": "nod"},
        expected_types={"domain-name"},
        calls=["/domaintools/v1/feed/nod"],
        description="the Newly Observed Domains feed becomes domain-name observables",
    ),
]
