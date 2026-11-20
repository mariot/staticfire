import hashlib
import uuid

from staticfire.connector_vendors import ConnectorSpec


def _file(cti) -> str:
    return cti.create_file_observable(hashlib.sha256(uuid.uuid4().bytes).hexdigest())["id"]


SPEC = ConnectorSpec(
    recipe="virustotal-downloader",
    connector="internal-enrichment/virustotal-downloader",
    env=lambda fake: {"VIRUSTOTAL_DOWNLOADER_API_KEY": "staticfire-fake-key"},
    enrich=_file,
    expected_types={"relationship:related-to"},
    calls=["/virustotal/api/v3/files/"],
    description="the sample of a file hash is downloaded and uploaded as an Artifact "
    "(attached file, not in the bundle) related to the file",
)
