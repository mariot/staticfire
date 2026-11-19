import uuid

from staticfire.connector_vendors import ConnectorSpec


def _intrusion_set(cti) -> tuple[str, str]:
    intrusion_set = cti.create_intrusion_set(f"staticfire group {uuid.uuid4().hex[:8]}")
    cti.add_uses_attack_pattern(intrusion_set["id"], "T1566", "Phishing")
    return intrusion_set["id"], "Intrusion-Set"


SPEC = ConnectorSpec(
    recipe="export-ttps-file-navigator",
    connector="internal-export-file/export-ttps-file-navigator",
    export=("application/vnd.mitre.navigator+json", "entity"),
    export_object=_intrusion_set,
    description="the techniques an intrusion set uses are exported as an ATT&CK Navigator layer",
)
