from staticfire.connector_vendors import ConnectorSpec

SPEC = ConnectorSpec(
    recipe="sentinelone-intel",
    connector="stream/sentinelone-intel",
    env=lambda fake: {
        "SENTINELONE_INTEL_API_URL": "https://staticfire.sentinelone.net",
        "SENTINELONE_INTEL_API_KEY": "staticfire-fake-key",
        "SENTINELONE_INTEL_ACCOUNT_ID": "1000000000000000001",
    },
    calls=["/sentinelone-console/web/api/v2.1/threat-intelligence/iocs/stix"],
    description="indicators with a domain, URL, IPv4 or file hash pattern are pushed as STIX IOCs",
)
