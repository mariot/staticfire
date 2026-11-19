import json
import uuid

import httpx

from staticfire.connector_vendors import ConnectorSpec


def _artifact(cti) -> str:
    """An artifact with an imported file (a small fake executable), as the connector needs."""
    content = b"MZ\x90\x00" + uuid.uuid4().bytes * 8
    operations = {
        "query": "mutation ($file: Upload!) { artifactImport(file: $file) { id } }",
        "variables": {"file": None},
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
        files={"0": (f"sample-{uuid.uuid4().hex[:8]}.exe", content, "application/x-dosexec")},
    )
    payload = cti.http.send(request).json()
    if payload.get("errors"):
        raise RuntimeError(f"artifact import: {payload['errors'][:3]}")
    return payload["data"]["artifactImport"]["id"]


SPEC = ConnectorSpec(
    recipe="intezer-sandbox",
    connector="internal-enrichment/intezer-sandbox",
    env=lambda fake: {"INTEZER_SANDBOX_API_KEY": "staticfire-fake-key"},
    enrich=_artifact,
    calls=["/intezer/api/v2-0/analyze", "/intezer/api/v2-0/analyses/"],
    description="an artifact's file is analysed (token, upload, polling until the verdict), "
    "then an external reference, a family label and a verdict label are added to it",
)
