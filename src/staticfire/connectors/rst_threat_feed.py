from staticfire.connector_vendors import ConnectorSpec
from staticfire.vendors import Rule

TECHNIQUES = {
    "T1566": "Phishing",
    "T1059": "Command and Scripting Interpreter",
    "T1003": "OS Credential Dumping",
    "T1027": "Obfuscated Files or Information",
}


def _mitre_bundle(fake) -> list[Rule]:
    """The ATT&CK bundle the connector downloads from GitHub to map technique ids to names."""
    objects = [
        {
            "type": "attack-pattern",
            "spec_version": "2.1",
            "id": f"attack-pattern--00000000-0000-4000-8000-{index:012d}",
            "name": name,
            "created": "2020-01-01T00:00:00.000Z",
            "modified": "2020-01-01T00:00:00.000Z",
            "external_references": [{"source_name": "mitre-attack", "external_id": external_id}],
        }
        for index, (external_id, name) in enumerate(TECHNIQUES.items())
    ]
    path = "/github/mitre/cti/master/enterprise-attack/enterprise-attack.json"
    return [Rule(path, {"type": "bundle", "id": "bundle--staticfire", "objects": objects})]


SPEC = ConnectorSpec(
    recipe="rst-threat-feed",
    connector="external-import/rst-threat-feed",
    env=lambda fake: {
        "RST_THREAT_FEED_APIKEY": "staticfire-fake-key",
        # the feed download passes proxies={"https": ""} to requests: it ignores HTTPS_PROXY
        "RST_THREAT_FEED_BASEURL": fake.http_url("rstcloud") + "/v1",
        "RST_THREAT_FEED_CREATE_MITRE_TTPS": "true",
    },
    rules=_mitre_bundle,
    expected_types={
        "indicator",
        "malware",
        "intrusion-set",
        "campaign",
        "tool",
        "attack-pattern",
        "vulnerability",
        "relationship:indicates",
        "relationship:related-to",
    },
    calls=["/rstcloud/v1/ip", "/rstcloud/v1/domain", "/rstcloud/v1/url", "/rstcloud/v1/hash"],
    description="the four daily feeds (ip, domain, url, hash; gzip JSON lines) become indicators "
    "indicating malware, groups, campaigns, tools, MITRE and custom techniques and CVEs; "
    "the ATT&CK mapping is downloaded from GitHub (it leaves mitre_ttp_mapping.json in src/)",
)
