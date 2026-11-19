import base64
import hashlib
import json
import uuid

import httpx

from staticfire.connector_vendors import ConnectorSpec

# The name the platform knows the connector by: both specs share its id, and renaming it
# between two runs loses the enrichment message of the run
_ENV = {"JOE_SANDBOX_API_KEY": "staticfire-fake-key", "CONNECTOR_NAME": "staticfire joe-sandbox"}


_TYPES = {"domain-name", "ipv4-addr", "url", "note", "relationship:communicates-with"}


def _new_artifact(cti) -> str:
    """An artifact carrying a sample, attached as a file as a user uploading it would (OpenCTI
    only stores a payload when enrichment is asked, a moment too late for the connector)."""
    content = f"MZ staticfire {uuid.uuid4()}".encode()
    artifact = cti.graphql(
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
    operations = {
        "query": "mutation ($id: ID!, $file: Upload!) {"
        " stixCoreObjectEdit(id: $id) { importPush(file: $file) { id } } }",
        "variables": {"id": artifact, "file": None},
    }
    cti.http.cookies.clear()
    request = httpx.Request(
        "POST",
        f"{cti.url}/graphql",
        headers={
            "Authorization": cti.http.headers["Authorization"],
            "apollo-require-preflight": "true",
        },
        data={"operations": json.dumps(operations), "map": json.dumps({"0": ["variables.file"]})},
        files={"0": ("sample.exe", content, "application/x-dosexec")},
    )
    response = cti.http.send(request)
    response.raise_for_status()
    if response.json().get("errors"):
        raise RuntimeError(f"sample upload failed: {response.json()['errors'][:2]}")
    return artifact


SPECS = [
    ConnectorSpec(
        recipe="joe-sandbox",
        connector="internal-enrichment/joe-sandbox",
        env=lambda fake: _ENV,
        enrich=("Url", "https://staticfire-joe.example.com/payload.exe"),
        expected_types={
            "domain-name",
            "ipv4-addr",
            "url",
            "note",
            "relationship:communicates-with",
        },
        calls=["/joe-sandbox/api/v2/submission/new", "/joe-sandbox/api/v2/analysis/download"],
        description="a URL is submitted to Joe Sandbox, then its malware config note, contacted "
        "domains, URLs and IPs, YARA labels and report files enrich the observable",
    ),
    ConnectorSpec(
        recipe="joe-sandbox-artifact",
        connector="internal-enrichment/joe-sandbox",
        env=lambda fake: _ENV,
        enrich=_new_artifact,
        expected_types={
            "domain-name",
            "ipv4-addr",
            "url",
            "note",
            "relationship:communicates-with",
        },
        calls=["/joe-sandbox/api/v2/submission/new", "/joe-sandbox/api/v2/analysis/download"],
        description="an artifact's sample is submitted to Joe Sandbox, then its malware config "
        "note, contacted domains, URLs and IPs, YARA labels and report files enrich the artifact",
    ),
]
