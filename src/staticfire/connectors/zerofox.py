from staticfire.connector_vendors import ConnectorSpec

SPEC = ConnectorSpec(
    recipe="zerofox",
    connector="external-import/zerofox",
    env=lambda fake: {
        "ZEROFOX_USERNAME": "staticfire@example.com",
        "ZEROFOX_PASSWORD": "staticfire-fake-password",
    },
    expected_types={
        "infrastructure",
        "malware",
        "indicator",
        "vulnerability",
        "ipv4-addr",
        "url",
        "autonomous-system",
        "location",
        "x509-certificate",
        "relationship:consists-of",
        "relationship:indicates",
    },
    calls=["/zerofox/auth/token/", "/zerofox/cti/"],
    description="every CTI feed (two pages each) after a JWT login: infrastructure, malware, CVEs",
)
