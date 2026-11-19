import json
import uuid

import httpx

from staticfire import config
from staticfire.connector_vendors import ConnectorSpec

# libmagic is a system library the machine may lack, and python-magic does not load without it:
# a module of the same name, using the file(1) command, stands in for it
MAGIC_SHIM = """\
import subprocess


def from_buffer(buffer, mime=False):
    option = "--mime-type" if mime else "--brief"
    out = subprocess.run(["/usr/bin/file", option, "-b", "-"], input=buffer, capture_output=True)
    return out.stdout.decode().strip()


def from_file(path, mime=False):
    with open(path, "rb") as stream:
        return from_buffer(stream.read(), mime)
"""
SHIM_DIR = config.STATE_DIR / "shims" / "hatching-triage-sandbox"


def _env(fake) -> dict[str, str]:
    SHIM_DIR.mkdir(parents=True, exist_ok=True)
    (SHIM_DIR / "magic.py").write_text(MAGIC_SHIM)
    return {
        "PYTHONPATH": str(SHIM_DIR),
        "HATCHING_TRIAGE_SANDBOX_TOKEN": "staticfire-fake-key",
        "HATCHING_TRIAGE_SANDBOX_MAX_ATTEMPTS": "2",
    }


def _artifact(cti) -> str:
    """An artifact holding a file, whose sha256 the connector looks up in Triage."""
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
                b"MZ" + bytes(range(128)),
                "application/x-msdownload",
            )
        },
    )
    payload = cti.http.send(request).json()
    if payload.get("errors"):
        raise RuntimeError(f"artifact upload errors: {payload['errors'][:3]}")
    return payload["data"]["artifactImport"]["id"]


SPEC = ConnectorSpec(
    recipe="hatching-triage-sandbox",
    connector="internal-enrichment/hatching-triage-sandbox",
    env=_env,
    enrich=_artifact,
    expected_types={
        "note",
        "ipv4-addr",
        "domain-name",
        "url",
        "email-addr",
        "attack-pattern",
        "relationship:communicates-with",
        "relationship:related-to",
        "relationship:uses",
    },
    calls=[
        "/hatching-triage/api/v0/search",
        "/hatching-triage/api/v1/samples/",
        "/hatching-triage/api/v0/samples/",
    ],
    description="an artifact found in an existing Triage analysis: tags, C2 config note, "
    "network IOCs, TTPs (the extracted dump goes up as an artifact)",
)
