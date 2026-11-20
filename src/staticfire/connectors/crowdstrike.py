from staticfire.connector_vendors import ConnectorSpec

SPEC = ConnectorSpec(
    recipe="crowdstrike-cti",
    connector="external-import/crowdstrike",
    env=lambda fake: {
        "CROWDSTRIKE_CLIENT_ID": "staticfire-client",
        "CROWDSTRIKE_CLIENT_SECRET": "staticfire-secret",
        "CROWDSTRIKE_SCOPES": (
            "actor,report,indicator,malware,vulnerability,yara_master,snort_suricata_master"
        ),
        # The ATT&CK dataset the connector loads at startup, served by ofapi
        "CROWDSTRIKE_ATTACK_ENTERPRISE_URL": "https://attack.staticfire.test/enterprise-attack.json",
        "CROWDSTRIKE_INDICATOR_EXCLUDE_TYPES": "password,username",
        "CROWDSTRIKE_REPORT_GUESS_RELATIONS": "true",
    },
    expected_types={
        "intrusion-set",
        "malware",
        "attack-pattern",
        "location",
        "identity",
        "report",
        "indicator",
        "ipv4-addr",
        "domain-name",
        "vulnerability",
        "relationship:indicates",
        "relationship:uses",
        "relationship:targets",
    },
    calls=[
        "/crowdstrike/intel/combined/actors/v1",
        "/crowdstrike/intel/combined/reports/v1",
        "/crowdstrike/intel/combined/indicators/v1",
        "/crowdstrike/intel/combined/malware/v1",
        "/crowdstrike/intel/queries/vulnerabilities/v1",
        "/crowdstrike/intel/entities/rules-latest-files/v1",
    ],
    description="Falcon Intel actors, reports, indicators, malware, CVEs and YARA/Snort rules",
)
