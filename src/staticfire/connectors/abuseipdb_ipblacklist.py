from staticfire.connector_vendors import ConnectorSpec

SPEC = ConnectorSpec(
    recipe="abuseipdb-ipblacklist",
    connector="external-import/abuseipdb-ipblacklist",
    env=lambda fake: {
        "ABUSEIPDB_API_KEY": "staticfire-fake-key",
        "ABUSEIPDB_SCORE": "75",
        "ABUSEIPDB_LIMIT": "100",
    },
    expected_types={"ipv4-addr", "ipv6-addr", "identity"},
    calls=["/abuseipdb/api/v2/blacklist"],
    description="the blacklist (IPv4 and IPv6 above the score) becomes scored observables",
)
