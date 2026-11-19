from staticfire.connector_vendors import ConnectorSpec

ENV = {
    "REVERSINGLABS_SPECTRA_ANALYZE_URL": "https://spectra-analyze.staticfire.test",
    "REVERSINGLABS_SPECTRA_ANALYZE_TOKEN": "staticfire-fake-key",
}

SPECS = [
    ConnectorSpec(
        recipe="reversinglabs-spectra-analyze",
        connector="internal-enrichment/reversinglabs-spectra-analyze",
        env=lambda fake: ENV,
        enrich=("IPv4-Addr", "185.220.101.47"),
        expected_types={
            "indicator",
            "malware",
            "note",
            "relationship:based-on",
            "relationship:related-to",
        },
        calls=[
            "/reversinglabs/api/network-threat-intel/ip/185.220.101.47/report/",
            "/reversinglabs/api/network-threat-intel/ip/185.220.101.47/downloaded_files/",
        ],
        description="an IP gets its appliance report, downloaded files, URLs and resolutions",
    ),
    ConnectorSpec(
        recipe="reversinglabs-spectra-analyze-domain",
        connector="internal-enrichment/reversinglabs-spectra-analyze",
        env=lambda fake: ENV,
        enrich=("Domain-Name", "staticfire-rl-analyze.example.org"),
        expected_types={"indicator", "malware"},
        calls=["/reversinglabs/api/network-threat-intel/domain/"],
        description="a domain gets its appliance report, resolutions and downloaded files",
    ),
    ConnectorSpec(
        recipe="reversinglabs-spectra-analyze-url",
        connector="internal-enrichment/reversinglabs-spectra-analyze",
        env=lambda fake: ENV,
        enrich=("Url", "https://staticfire-rl-analyze.example.org/payload"),
        expected_types={"indicator", "malware"},
        calls=[
            "/reversinglabs/api/network-threat-intel/url/",
            "/reversinglabs/api/uploads/",
            "/reversinglabs/api/uploads/v2/url-samples/",
            "/reversinglabs/api/samples/v3/",
        ],
        description="a URL is submitted to the appliance, polled, classified and reported",
    ),
    ConnectorSpec(
        recipe="reversinglabs-spectra-analyze-file",
        connector="internal-enrichment/reversinglabs-spectra-analyze",
        env=lambda fake: ENV,
        enrich=("StixFile", "7d865e959b2466918c9863afca942d0fb89d7c9ac0c99bafc3749504ded97730"),
        expected_types={"indicator", "malware"},
        calls=["/reversinglabs/api/samples/v2/list/details/"],
        description="a known hash gets its detailed appliance report (artifact upload is not "
        "exercised)",
    ),
]
