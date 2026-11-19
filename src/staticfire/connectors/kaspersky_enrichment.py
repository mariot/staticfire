from staticfire.connector_vendors import ConnectorSpec

# One name for every spec: they share the connector's id, and renaming it between two runs
# loses the enrichment message of the run
_ENV = {
    "KASPERSKY_API_KEY": "staticfire-fake-key",
    "CONNECTOR_NAME": "staticfire kaspersky-enrichment",
    "KASPERSKY_IPV4_SECTIONS": (
        "LicenseInfo,Zone,IpGeneralInfo,FilesDownloadedFromIp,HostedUrls,IpWhoIs,"
        "IpDnsResolutions,Industries"
    ),
    "KASPERSKY_DOMAIN_SECTIONS": (
        "LicenseInfo,Zone,DomainGeneralInfo,DomainDnsResolutions,FilesDownloaded,"
        "FilesAccessed,Industries"
    ),
    "KASPERSKY_FILE_SECTIONS": (
        "LicenseInfo,Zone,FileGeneralInfo,DetectionsInfo,FileDownloadedFromUrls,"
        "Industries,FileNames"
    ),
    "KASPERSKY_URL_SECTIONS": (
        "LicenseInfo,Zone,UrlGeneralInfo,FilesDownloaded,FilesAccessed,Industries"
    ),
}

SPECS = [
    ConnectorSpec(
        recipe="kaspersky-enrichment",
        connector="internal-enrichment/kaspersky-enrichment",
        env=lambda fake: _ENV,
        enrich=("IPv4-Addr", "185.220.101.39"),
        expected_types={
            "location",
            "autonomous-system",
            "domain-name",
            "url",
            "file",
            "identity",
            "relationship:located-at",
            "relationship:belongs-to",
            "relationship:resolves-to",
            "relationship:related-to",
        },
        calls=["/kaspersky/api/ip/"],
        description="an address gets its score, labels, country, AS, resolutions, hosted URLs, "
        "downloaded files and industries",
    ),
    ConnectorSpec(
        recipe="kaspersky-enrichment-domain",
        connector="internal-enrichment/kaspersky-enrichment",
        env=lambda fake: _ENV,
        enrich=("Domain-Name", "staticfire-kaspersky.example.com"),
        expected_types={"ipv4-addr", "url", "file", "relationship:resolves-to"},
        calls=["/kaspersky/api/domain/"],
        description="a domain gets its score, labels, resolutions, downloaded and accessed files",
    ),
    ConnectorSpec(
        recipe="kaspersky-enrichment-file",
        connector="internal-enrichment/kaspersky-enrichment",
        env=lambda fake: _ENV,
        enrich=("StixFile", "0f3ea4fa5bd0c7d0b0cb4b2e4cf7de6a4d1cf7c4ac6f6d4a7d4c0ad2cfd7a111"),
        expected_types={"note", "url", "identity", "relationship:related-to"},
        calls=["/kaspersky/api/hash/"],
        description="a file hash gets its score, hashes, size, names, detections note and URLs",
    ),
    ConnectorSpec(
        recipe="kaspersky-enrichment-url",
        connector="internal-enrichment/kaspersky-enrichment",
        env=lambda fake: _ENV,
        enrich=("Url", "http://staticfire-kaspersky.example.com/payload.bin"),
        expected_types={"domain-name", "file", "relationship:related-to"},
        calls=["/kaspersky/api/url/"],
        description="a URL gets its score, labels, host, downloaded and accessed files",
    ),
]
