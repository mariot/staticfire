from staticfire.connector_vendors import ConnectorSpec

SPEC = ConnectorSpec(
    recipe="crowdsec",
    connector="internal-enrichment/crowdsec",
    env=lambda fake: {
        "CROWDSEC_KEY": "staticfire-fake-key",
        "CROWDSEC_INDICATOR_CREATE_FROM": "malicious,suspicious,known",
        "CROWDSEC_ATTACK_PATTERN_CREATE_FROM_MITRE": "true",
        "CROWDSEC_CREATE_NOTE": "true",
    },
    enrich=("IPv4-Addr", "198.51.100.88"),
    expected_types={
        "indicator",
        "attack-pattern",
        "vulnerability",
        "location",
        "note",
        "sighting",
        "relationship:based-on",
        "relationship:indicates",
        "relationship:targets",
    },
    calls=["/crowdsec/v2/smoke/"],
    description="an IP gets CrowdSec indicator, MITRE attack patterns, CVEs, countries and note",
)
