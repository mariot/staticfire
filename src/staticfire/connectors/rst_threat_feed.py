from staticfire.connector_vendors import ConnectorSpec

SPEC = ConnectorSpec(
    recipe="rst-threat-feed",
    connector="external-import/rst-threat-feed",
    env=lambda fake: {
        "RST_THREAT_FEED_APIKEY": "staticfire-fake-key",
        # the feed download passes proxies={"https": ""} to requests: it ignores HTTPS_PROXY
        "RST_THREAT_FEED_BASEURL": fake.http_url("rstcloud") + "/v1",
        # the ATT&CK bundle it maps technique ids with comes from ofapi's mitre/cti repository
        "RST_THREAT_FEED_CREATE_MITRE_TTPS": "true",
    },
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
