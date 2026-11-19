from staticfire.connector_vendors import ConnectorSpec

SPEC = ConnectorSpec(
    recipe="ransomwarelive",
    connector="external-import/ransomwarelive",
    env=lambda fake: {
        "RANSOMWARELIVE_CREATE_THREAT_ACTOR": "true",
        "RANSOMWARELIVE_CREATE_CAMPAIGN": "true",
        "RANSOMWARELIVE_CREATE_LEAK_SITE_DOMAINS": "true",
        "RANSOMWARELIVE_CREATE_LEAK_POST_REFS": "true",
    },
    expected_types={
        "identity",
        "intrusion-set",
        "threat-actor",
        "campaign",
        "report",
        "domain-name",
        "relationship:targets",
    },
    calls=["/ransomwarelive/v2/groups", "/ransomwarelive/v2/recentvictims"],
    description="recent victims become identities with intrusion sets, actors, campaigns "
    "and reports",
)
