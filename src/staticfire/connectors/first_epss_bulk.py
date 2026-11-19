from staticfire import config, ops
from staticfire.connector_vendors import ConnectorSpec

# CVEs scored by the fake file (ofapi first_epss module)
KNOWN_CVES = ["CVE-2021-44228", "CVE-2023-4863", "CVE-2024-3400", "CVE-2023-34362"]


def _seed_vulnerabilities() -> None:
    """The connector only scores the vulnerabilities OpenCTI already holds."""
    profile = config.load_profile()
    for name in config.list_profiles():
        if profile.opencti_url:
            break
        profile = config.load_profile(name)
    cti = ops.cti_client(profile)
    for cve in KNOWN_CVES:
        cti.graphql(
            """mutation ($input: VulnerabilityAddInput!) { vulnerabilityAdd(input: $input) {
                 id } }""",
            {"input": {"name": cve}},
        )


def _env(fake) -> dict[str, str]:
    _seed_vulnerabilities()
    return {"FIRST_EPSS_API_BASE_URL": "https://epss.cyentia.com"}


SPEC = ConnectorSpec(
    recipe="first-epss-bulk",
    connector="external-import/first-epss-bulk",
    env=_env,
    expected_types={"vulnerability", "identity"},
    calls=["/first-epss/epss_scores-"],
    description="the daily EPSS file (gzip CSV) scores the CVEs already in OpenCTI "
    "(seeded by the test)",
)
