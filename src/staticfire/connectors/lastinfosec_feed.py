from staticfire.connector_vendors import ConnectorSpec

_ENV = {"CONFIG_LIS_APIKEY": "staticfire-fake-key"}

SPECS = [
    ConnectorSpec(
        recipe="lastinfosec-feed",
        connector="external-import/lastinfosec-feed",
        env=lambda fake: {**_ENV, "CONFIG_LIS_CTI_ENABLED": "true"},
        expected_types={"indicator", "malware", "relationship:indicates"},
        calls=["/lastinfosec/v2/stix21/getbyminutes/"],
        description="the CTI feed (STIX bundles of indicators indicating a malware)",
    ),
    ConnectorSpec(
        recipe="lastinfosec-feed-cve",
        connector="external-import/lastinfosec-feed",
        env=lambda fake: {**_ENV, "CONFIG_LIS_CVE_ENABLED": "true"},
        expected_types={"vulnerability"},
        calls=["/lastinfosec/v2/stix21/vulnerabilities/getlasthour"],
        description="the CVE feed (STIX bundle of vulnerabilities)",
    ),
    ConnectorSpec(
        recipe="lastinfosec-feed-tactic",
        connector="external-import/lastinfosec-feed",
        env=lambda fake: {**_ENV, "CONFIG_LIS_TACTIC_ENABLED": "true"},
        expected_types={"intrusion-set", "attack-pattern", "relationship:uses"},
        calls=["/lastinfosec/v2/stix21/tactic/getlast24hour"],
        description="the tactic feed (intrusion set using attack patterns)",
    ),
]
