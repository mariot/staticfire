import hashlib
import uuid

from staticfire.connector_vendors import ConnectorSpec


def _new_file(cti) -> str:
    sha256 = hashlib.sha256(f"staticfire wildfire {uuid.uuid4()}".encode()).hexdigest()
    return cti.create_file_observable(sha256, "sample.exe")["id"]


SPEC = ConnectorSpec(
    recipe="paloalto-wildfire",
    connector="internal-enrichment/paloalto-wildfire",
    env=lambda fake: {"PALOALTO_WILDFIRE_API_KEY": "staticfire-fake-key"},
    enrich=_new_file,
    expected_types={"malware-analysis", "identity", "file"},
    calls=["/paloalto-wildfire/publicapi/get/verdict", "/paloalto-wildfire/publicapi/get/report"],
    description="a file hash known as malware to WildFire gets its score, label, hashes, size "
    "and a malware analysis object",
)
