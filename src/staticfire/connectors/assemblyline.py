import base64
import hashlib
import uuid

from staticfire.connector_vendors import ConnectorSpec

# sha256("password"): the file the fake AssemblyLine already analysed
KNOWN_SHA256 = "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8"

ENV = {
    "ASSEMBLYLINE_URL": "https://assemblyline.staticfire.test",
    "ASSEMBLYLINE_USER": "staticfire",
    "ASSEMBLYLINE_APIKEY": "staticfire-fake-key",
    "ASSEMBLYLINE_TIMEOUT": "120",
}


def _new_artifact(cti) -> str:
    """An artifact carrying a file AssemblyLine has never seen (its content in payload_bin)."""
    content = f"MZ staticfire {uuid.uuid4()}".encode()
    return cti.graphql(
        """mutation ($payload: String!, $sha256: String!) {
             stixCyberObservableAdd(type: "Artifact",
               Artifact: { payload_bin: $payload, mime_type: "application/x-dosexec",
                           hashes: [{ algorithm: "SHA-256", hash: $sha256 }],
                           x_opencti_additional_names: ["sample.exe"] }) { id } }""",
        {
            "payload": base64.b64encode(content).decode(),
            "sha256": hashlib.sha256(content).hexdigest(),
        },
    )["stixCyberObservableAdd"]["id"]


SPECS = [
    ConnectorSpec(
        recipe="assemblyline",
        connector="internal-enrichment/assemblyline",
        env=lambda fake: ENV,
        enrich=lambda cti: cti.create_file_observable(KNOWN_SHA256, "sample.exe")["id"],
        expected_types={"malware-analysis", "domain-name", "ipv4-addr", "url"},
        calls=[
            "/assemblyline/api/v4/search/submission/",
            "/assemblyline/api/v4/submission/summary/",
        ],
        description="a file already analysed gets its malicious IOCs, family, ATT&CK techniques "
        "and a malware analysis from the existing AssemblyLine submission",
    ),
    ConnectorSpec(
        recipe="assemblyline-submit",
        connector="internal-enrichment/assemblyline",
        env=lambda fake: ENV,
        enrich=_new_artifact,
        expected_types={"malware-analysis", "domain-name", "ipv4-addr", "url"},
        calls=[
            "/assemblyline/api/v4/submit/",
            "/assemblyline/api/v4/submission/summary/",
        ],
        description="an artifact never analysed is submitted to AssemblyLine, then its results "
        "become IOCs, a family, ATT&CK techniques and a malware analysis",
    ),
]
