import json
import tempfile
import uuid
from datetime import UTC, datetime
from pathlib import Path

from staticfire.connector_vendors import ConnectorSpec
from staticfire.runner import ID_NAMESPACE


def _stix_bundle() -> dict:
    now = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    token = uuid.uuid4().hex[:8]
    ip = f"198.51.100.{int(token[:2], 16) % 254 + 1}"

    def sdo(kind: str, **fields) -> dict:
        return {
            "type": kind,
            "spec_version": "2.1",
            "id": f"{kind}--{uuid.uuid4()}",
            "created": now,
            "modified": now,
            **fields,
        }

    author = sdo("identity", name=f"Diode source {token}", identity_class="organization")
    malware = sdo("malware", name=f"DiodeMalware {token}", is_family=True)
    indicator = sdo(
        "indicator",
        name=ip,
        pattern=f"[ipv4-addr:value = '{ip}']",
        pattern_type="stix",
        valid_from=now,
        created_by_ref=author["id"],
    )
    link = sdo(
        "relationship",
        relationship_type="indicates",
        source_ref=indicator["id"],
        target_ref=malware["id"],
    )
    return {
        "type": "bundle",
        "id": f"bundle--{uuid.uuid4()}",
        "objects": [author, malware, indicator, link],
    }


def _env(fake) -> dict[str, str]:
    """Bundles as a connector on the other side of the diode drops them in a directory.

    The bundle names the importing connector itself as its source: the works it opens are then
    the ones the recipe looks at.
    """
    folder = Path(tempfile.mkdtemp(prefix="staticfire-diode-"))
    source = {
        "id": str(uuid.uuid5(ID_NAMESPACE, "staticfire:connector:diode-import")),
        "name": "staticfire diode-import",
        "type": "EXTERNAL_IMPORT",
        "scope": ["diode-import"],
        "auto": False,
    }
    message = {
        "connector": source,
        "applicant_id": "staticfire-source-user",
        "update": False,
        "bundle": _stix_bundle(),
    }
    (folder / "bundle-1.json").write_text(json.dumps(message))
    # a file that is not a bundle: the connector drops it
    (folder / "broken.json").write_text("{not json")
    return {
        "DIODE_IMPORT_GET_FROM_DIRECTORY_PATH": str(folder),
        # the compose file maps made-up applicants to made-up users
        "DIODE_IMPORT_APPLICANT_MAPPINGS": "",
        # pushes to the RabbitMQ OpenCTI advertises (a Docker name), ignoring MQ_HOST
    }


SPEC = ConnectorSpec(
    recipe="diode-import",
    connector="external-import/diode-import",
    env=_env,
    expected_types={"indicator", "malware", "identity", "relationship:indicates"},
    description="reads STIX bundle files dropped in a directory (S3 mode not exercised), "
    "registers the source connector and imports them in a work",
)
