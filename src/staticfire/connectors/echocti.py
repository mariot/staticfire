from staticfire.connector_vendors import ConnectorSpec

_ENV = {"ECHOCTI_CLIENT_ID": "staticfire", "ECHOCTI_CLIENT_SECRET": "staticfire-fake-secret"}

SPECS = [
    ConnectorSpec(
        recipe="echocti",
        connector="external-import/echocti",
        env=lambda fake: {**_ENV, "ECHOCTI_TYPE": "ip,url,hash,ip-range"},
        expected_types={"indicator", "identity"},
        calls=["/echocti/ioc2/feeds"],
        description="one feed request per IOC type (ip, url, hash, ip-range) becomes indicators",
    ),
    ConnectorSpec(
        recipe="echocti-all",
        connector="external-import/echocti",
        env=lambda fake: {**_ENV, "ECHOCTI_TYPE": "all"},
        expected_types={"indicator", "identity"},
        calls=["/echocti/ioc2/feeds"],
        description="one untyped feed request: the connector detects each IOC's type itself",
    ),
]
