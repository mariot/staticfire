import uuid

from staticfire.connector_vendors import ConnectorSpec


def _yara_indicator(cti) -> tuple[str, str]:
    name = f"staticfire_{uuid.uuid4().hex[:8]}"
    rule = f'rule {name} {{ strings: $a = "staticfire" condition: $a }}'
    return cti.create_indicator(name, rule, "StixFile", pattern_type="yara")["id"], "Indicator"


SPEC = ConnectorSpec(
    recipe="export-file-yara",
    connector="internal-export-file/export-file-yara",
    export=("text/yara+plain", "list"),
    export_object=_yara_indicator,
    description="a list export of a YARA indicator to a rules file",
)
