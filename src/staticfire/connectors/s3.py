import json
import uuid
from datetime import UTC, datetime

from staticfire.connector_vendors import ConnectorSpec

BUCKET = "staticfire-s3-import"
REGION = "eu-west-1"


def _vulnerability_bundle() -> bytes:
    now = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    cve = f"CVE-2026-{uuid.uuid4().int % 90000 + 10000}"
    vulnerability = {
        "type": "vulnerability",
        "spec_version": "2.1",
        "id": f"vulnerability--{uuid.uuid4()}",
        "created": now,
        "modified": now,
        "name": cve,
        "description": "Remote code execution in a staticfire test product.",
        "external_references": [{"source_name": "cve", "external_id": cve}],
        "x_severity": 4,
        "x_cvss_v3": 9.8,
        "x_zero_day": True,
    }
    bundle = {"type": "bundle", "id": f"bundle--{uuid.uuid4()}", "objects": [vulnerability]}
    return json.dumps(bundle).encode()


def _env(fake) -> dict[str, str]:
    # The connector deletes what it imports: every run seeds the bucket again
    for _ in range(2):
        bundle = fake.http.get("/fixtures/stix-bundle.json").raise_for_status().content
        fake.s3_put(BUCKET, f"ACI_TI/{uuid.uuid4()}.json", bundle, REGION)
    fake.s3_put(BUCKET, f"ACI_Vuln/{uuid.uuid4()}.json", _vulnerability_bundle(), REGION)
    return {
        "S3_ACCESS_KEY_ID": "staticfire-fake-key",
        "S3_SECRET_ACCESS_KEY": "staticfire-fake-secret",
        "S3_BUCKET_NAME": BUCKET,
        "S3_REGION": REGION,
        "S3_BUCKET_PREFIXES": "ACI_TI,ACI_Vuln",
    }


SPEC = ConnectorSpec(
    recipe="s3",
    connector="external-import/s3",
    env=_env,
    expected_types={
        "report",
        "indicator",
        "malware",
        "intrusion-set",
        "attack-pattern",
        "vulnerability",
        "relationship:uses",
        "relationship:indicates",
    },
    calls=["/aws/ACI_TI/", "/aws/ACI_Vuln/"],
    description="STIX bundles of two prefixes (threat intel, vulnerability) are read from an "
    "emulated S3 bucket and sent; the connector deletes each file once imported, so every run "
    "seeds the bucket again",
)
