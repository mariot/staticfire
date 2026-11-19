from staticfire.connector_vendors import ConnectorSpec

COLLECTIONS = ["APT_THREAT", "APT_THREAT_ACTOR", "OSI_VULNERABILITY", "SUSPICIOUS_IP_TOR_NODE"]

SPEC = ConnectorSpec(
    recipe="group-ib",
    connector="external-import/group-ib",
    env=lambda fake: {
        "TI_API_USERNAME": "staticfire@example.com",
        "TI_API_TOKEN": "staticfire-fake-key",
        **{f"TI_API_COLLECTIONS_{name}_ENABLE": "true" for name in COLLECTIONS},
    },
    expected_types={
        "report",
        "threat-actor",
        "malware",
        "attack-pattern",
        "vulnerability",
        "indicator",
        "ipv4-addr",
        "domain-name",
        "url",
        "file",
    },
    calls=["/group-ib/api/v2/sequence_list", "/group-ib/api/v2/apt/threat/updated"],
    description="deprecated Group-IB connector: apt/threat reports, actors, CVEs and Tor nodes",
)
