from staticfire.connector_vendors import ConnectorSpec

SPEC = ConnectorSpec(
    recipe="ransomfeed",
    connector="external-import/ransomfeed",
    expected_types={
        "report",
        "identity",
        "intrusion-set",
        "location",
        "domain-name",
        "indicator",
        "relationship:targets",
        "relationship:located-at",
        "relationship:belongs-to",
    },
    calls=["/ransomfeed/"],
    description="ransomware claims become reports on a gang, its victim, country, domain and hash",
)
