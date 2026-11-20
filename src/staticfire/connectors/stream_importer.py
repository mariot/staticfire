import json
import re
import time
import uuid
from urllib.parse import urlsplit

from staticfire.connector_vendors import ConnectorSpec

SRC_BUCKET = "sfminio-importer-src"
DST_BUCKET = "sfminio-importer-dst"
FOLDER = "opencti-stream"
# STIX identifiers: UUIDv5 of the canonical JSON of the contributing properties
_NAMESPACE = uuid.UUID("00abedb4-aa42-466c-9c01-fed23315a9b7")


def _stix_id(kind: str, **properties: str) -> str:
    canonical = json.dumps(properties, sort_keys=True, separators=(",", ":"))
    return f"{kind}--{uuid.uuid5(_NAMESPACE, canonical)}"


def _events() -> bytes:
    """Stream events as the stream-exporter writes them: creation of a domain and of an
    indicator on it."""
    token = uuid.uuid4().hex[:8]
    domain = f"sf-{token}.example.com"
    now = time.strftime("%Y-%m-%dT%H:%M:%S.000Z", time.gmtime())
    pattern = f"[domain-name:value = '{domain}']"
    objects = [
        {
            "type": "domain-name",
            "spec_version": "2.1",
            "id": _stix_id("domain-name", value=domain),
            "value": domain,
        },
        {
            "type": "indicator",
            "spec_version": "2.1",
            "id": _stix_id("indicator", pattern=pattern),
            "created": now,
            "modified": now,
            "name": domain,
            "pattern": pattern,
            "pattern_type": "stix",
            "valid_from": now,
        },
    ]
    stamp = round(time.time() * 1000)
    lines = [
        {"id": f"{stamp}-{index}", "type": "create", "data": data}
        for index, data in enumerate(objects)
    ]
    return ("\n".join(json.dumps(line) for line in lines) + "\n").encode()


def _env(fake) -> dict[str, str]:
    http = fake.http
    http.put(f"/{SRC_BUCKET}")  # 409 when it exists
    # a file left by a run that failed would break the order the connector checks
    listing = http.get(f"/{SRC_BUCKET}", params={"list-type": "2", "prefix": f"{FOLDER}/"})
    for key in re.findall(r"<Key>([^<]+)</Key>", listing.text):
        http.delete(f"/{SRC_BUCKET}/{key}")
    name = f"{FOLDER}/stream_{round(time.time() * 1000)}_1.json"
    http.put(
        f"/{SRC_BUCKET}/{name}",
        content=_events(),
        headers={"Content-Type": "application/octet-stream"},
    ).raise_for_status()
    ofapi = urlsplit(fake.http_url())
    return {
        "MINIO_ENDPOINT": ofapi.hostname,
        "MINIO_PORT": str(ofapi.port),
        "MINIO_SRC_PATH": f"{SRC_BUCKET}/{FOLDER}",
        # the documented default (false) lists the folder itself, not its files: S3 answers
        # a prefix without a trailing slash with that "directory" only
        "MINIO_SRC_RECURSE": "true",
        "MINIO_DST_PATH": DST_BUCKET,
        "MINIO_ACCESS_KEY": "staticfire",
        "MINIO_SECRET_KEY": "staticfire-fake-key",
        "MINIO_SECURE": "false",
        "MINIO_CERT_CHECK": "false",
        "CONNECTOR_RUN_EVERY": "1m",
    }


SPEC = ConnectorSpec(
    recipe="stream-importer",
    connector="external-import/stream-importer",
    env=_env,
    proxy=False,
    # The connector publishes the events to the platform's RabbitMQ itself, outside its
    # work: what it did is read from what its account created
    opens_work=False,
    expected_types={"domain-name", "indicator"},
    calls=["/sfminio-importer-src"],
    description="a file of stream events in the bucket (an S3 emulation of ofapi standing in "
    "for MinIO) is pushed to RabbitMQ, ingested, then moved to the done bucket",
)
