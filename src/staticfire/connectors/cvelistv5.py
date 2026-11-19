import tempfile

from staticfire.connector_vendors import ConnectorSpec


def _env(fake) -> dict[str, str]:
    return {
        # a fresh clone every run, over HTTPS through the proxy
        "CVELISTV5_LOCAL_PATH": tempfile.mkdtemp(prefix="staticfire-cvelistv5-"),
        "CVELISTV5_HISTORY_START_YEAR": "2019",
    }


SPEC = ConnectorSpec(
    recipe="cvelistv5",
    connector="external-import/cvelistv5",
    env=_env,
    expected_types={"vulnerability", "software", "identity", "note", "relationship:has"},
    calls=["/github/CVEProject/cvelistV5.git/"],
    description="clones the CVE list repository (git over HTTPS) and imports its CVE records",
)
