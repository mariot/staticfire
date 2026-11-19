from staticfire.connector_vendors import ConnectorSpec

ENV = {
    "REVERSINGLABS_SPECTRA_INTEL_SUBMISSION_USERNAME": "staticfire",
    "REVERSINGLABS_SPECTRA_INTEL_SUBMISSION_PASSWORD": "staticfire-fake-key",
}
SHA256 = "1a79a4d60de6718e8e5b326e338ae533e3a8f2c4a0b6d5c9a7e1c1a2b3c4d5e6"

SPECS = [
    ConnectorSpec(
        recipe="reversinglabs-spectra-intel-submission",
        connector="internal-enrichment/reversinglabs-spectra-intel-submission",
        env=lambda fake: ENV,
        enrich=("StixFile", SHA256),
        expected_types={"indicator", "note", "malware", "relationship:based-on"},
        calls=[
            "/reversinglabs/api/dynamic/analysis/analyze/v1/query/json",
            "/reversinglabs/api/dynamic/analysis/report/v1/query/",
        ],
        description="a known hash is detonated in the sandbox; its report gives an indicator, "
        "malware, a note, ATT&CK references and the dropped files (artifact upload is not "
        "exercised)",
    ),
    ConnectorSpec(
        recipe="reversinglabs-spectra-intel-submission-url",
        connector="internal-enrichment/reversinglabs-spectra-intel-submission",
        env=lambda fake: ENV,
        enrich=("Url", "https://staticfire-rl-submit.example.org/payload.exe"),
        expected_types={"indicator", "malware", "note", "relationship:based-on"},
        calls=[
            "/reversinglabs/api/dynamic/analysis/analyze/v1/query/json",
            "/reversinglabs/api/dynamic/analysis/report/v1/query/url/sha1/",
        ],
        description="a URL is detonated in the sandbox and its report becomes an indicator, "
        "malware and a note",
    ),
]
