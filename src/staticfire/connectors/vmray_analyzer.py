import uuid

from staticfire.connector_vendors import ConnectorSpec


def _artifact(cti) -> str:
    content = b"MZ" + uuid.uuid4().bytes * 16
    return cti.create_artifact(content, "staticfire-sample.exe", "application/x-dosexec")


SPEC = ConnectorSpec(
    recipe="vmray-analyzer",
    connector="internal-enrichment/vmray-analyzer",
    env=lambda fake: {"VMRAY_ANALYZER_API_KEY": "staticfire-fake-key"},
    enrich=_artifact,
    expected_types={
        "note",
        "url",
        "domain-name",
        "ipv4-addr",
        "relationship:related-to",
        "relationship:communicates-with",
    },
    calls=["/vmray/rest/sample/submit", "/vmray/rest/analysis/"],
    description="an artifact is submitted, its analyses downloaded (archive, PDF and "
    "behaviour files attached to an external reference) and its network IOCs and malware "
    "configurations linked",
)
