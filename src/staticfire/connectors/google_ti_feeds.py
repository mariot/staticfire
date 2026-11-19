from staticfire.connector_vendors import ConnectorSpec

SPEC = ConnectorSpec(
    recipe="google-ti-feeds",
    connector="external-import/google-ti-feeds",
    env=lambda fake: {
        "GTI_API_KEY": "staticfire-fake-key",
        "GTI_IMPORT_REPORTS": "true",
        "GTI_IMPORT_THREAT_ACTORS": "true",
        "GTI_IMPORT_MALWARE_FAMILIES": "true",
        "GTI_IMPORT_SOFTWARE_TOOLKITS": "true",
        "GTI_IMPORT_VULNERABILITIES": "true",
        "GTI_IMPORT_CAMPAIGNS": "true",
        "GTI_REPORT_DOWNLOAD_PDF": "true",
        "GTI_CAMPAIGN_SUBENTITIES": "malware_families,attack_techniques,vulnerabilities,"
        "threat_actors,domains,files,urls,ip_addresses,software_toolkits",
    },
    expected_types={
        "report",
        "campaign",
        "intrusion-set",
        "malware",
        "tool",
        "vulnerability",
        "attack-pattern",
        "location",
        "identity",
        "note",
        "indicator",
        "domain-name",
        "ipv4-addr",
        "file",
        "url",
        "relationship:targets",
        "relationship:uses",
        "relationship:based-on",
        "relationship:indicates",
    },
    calls=["/virustotal/api/v3/collections"],
    timeout=600,
    description="GTI collections (reports with PDF, actors, malware, toolkits, vulnerabilities, "
    "campaigns) and their related IOCs and techniques",
)
