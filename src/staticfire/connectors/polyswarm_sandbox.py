import json
import uuid

import httpx

from staticfire.connector_vendors import ConnectorSpec


def _artifact(cti) -> str:
    """An artifact holding a file, which the connector downloads, scans and detonates."""
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
        data={
            "operations": json.dumps(operations),
            "map": json.dumps({"0": ["variables.file"]}),
        },
        files={
            "0": (
                f"sample-{uuid.uuid4().hex[:8]}.exe",
                b"MZ" + uuid.uuid4().bytes + bytes(range(128)),
                "application/x-msdownload",
            )
        },
    )
    payload = cti.http.send(request).json()
    if payload.get("errors"):
        raise RuntimeError(f"artifact upload errors: {payload['errors'][:3]}")
    return payload["data"]["artifactImport"]["id"]


SPEC = ConnectorSpec(
    recipe="polyswarm-sandbox",
    connector="internal-enrichment/polyswarm-sandbox",
    env=lambda fake: {
        "POLYSWARM_API_KEY": "staticfire-fake-key",
        "POLYSWARM_SANDBOX_PROVIDER": "both",
        "POLYSWARM_LLM_REPORT_ENABLED": "true",
        "POLYSWARM_POLL_INTERVAL": "1",
    },
    enrich=_artifact,
    expected_types={
        "malware",
        "indicator",
        "note",
        "attack-pattern",
        "ipv4-addr",
        "domain-name",
        "relationship:related-to",
        "relationship:uses",
        "relationship:indicates",
        "relationship:communicates-with",
    },
    calls=[
        "/polyswarm/v3/instance",
        "/polyswarm/v3/consumer/submission/",
        "/polyswarm/v3/sandbox/provider",
        "/polyswarm/v3/sandbox/sandboxtask",
        "/polyswarm/v3/reports",
    ],
    description=(
        "an artifact is scanned and detonated in Cape and Triage: notes, family, TTPs, network"
        " observables, plus JSON and PDF reports and an AI summary attached through the API"
    ),
    timeout=420,
)
