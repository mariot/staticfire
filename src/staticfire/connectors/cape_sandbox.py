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
SHIM_DIR = config.STATE_DIR / "shims" / "cape-sandbox"


def _env(fake) -> dict[str, str]:
    SHIM_DIR.mkdir(parents=True, exist_ok=True)
    (SHIM_DIR / "magic.py").write_text(MAGIC_SHIM)
    return {
        "PYTHONPATH": str(SHIM_DIR),
        "CAPE_SANDBOX_URL": "https://cape.example.com/apiv2",
        "CAPE_SANDBOX_TOKEN": "staticfire-fake-key",
        "CAPE_SANDBOX_COOLDOWN_TIME": "1",
        "CAPE_SANDBOX_LESS_NOISE": "false",
    }


def _artifact(cti) -> str:
    """An artifact holding a file, which the connector submits to the sandbox."""
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
    recipe="cape-sandbox",
    connector="internal-enrichment/cape-sandbox",
    env=_env,
    enrich=_artifact,
    expected_types={
        "attack-pattern",
        "note",
        "domain-name",
        "ipv4-addr",
        "relationship:uses",
        "relationship:communicates-with",
        "relationship:related-to",
    },
    calls=[
        "/cape/apiv2/tasks/create/file/",
        "/cape/apiv2/tasks/status/",
        "/cape/apiv2/tasks/get/report/",
        "/cape/apiv2/tasks/get/payloadfiles/",
    ],
    description="an artifact is detonated: TTPs, C2 configs, network (payloads go up as artifacts)",
)
