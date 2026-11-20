from staticfire.connector_vendors import ConnectorSpec

SPEC = ConnectorSpec(
    recipe="vulncheck",
    connector="external-import/vulncheck",
    env=lambda fake: {
        "VULNCHECK_API_KEY": "staticfire-fake-key",
        "VULNCHECK_DATA_SOURCES": "vulncheck-kev,nist-nvd2,epss,botnets,ransomware,"
        "threat-actors,ipintel,exploits,initial-access,snort,suricata",
        # the default scope leaves out software (a large volume on the real API)
        "CONNECTOR_SCOPE": "vulnerability,malware,threat-actor,infrastructure,location,"
        "ip-addr,indicator,external-reference,attack-pattern,course-of-action,"
        "x-mitre-data-source,report,software",
    },
    expected_types={
        "vulnerability",
        "malware",
        "threat-actor",
        "ipv4-addr",
        "infrastructure",
        "location",
        "software",
        "indicator",
    },
    calls=["/vulncheck/v3/index/"],
    timeout=600,
    description="KEV, NVD, EPSS, botnets, ransomware, threat actors, C2 IPs, exploits, "
    "initial access and Snort/Suricata rules each become their own work",
)
