import uuid

from staticfire.connector_vendors import ConnectorSpec


def _file_indicator(cti) -> list[str]:
    """An indicator on a new file name: Metras blocklists only take file paths."""
    name = f"sf-{uuid.uuid4().hex[:10]}.exe"
    cti.create_indicator(f"staticfire {name}", f"[file:name = '{name}']", "StixFile")
    return [name]


SPEC = ConnectorSpec(
    recipe="metras-stream",
    connector="stream/metras-stream",
    env=lambda fake: {"METRAS_API_KEY": "staticfire-fake-key"},
    stream=_file_indicator,
    calls=["/metras/api/v1/custom-blocklist"],
    description="an indicator on a file name becomes a Metras custom blocklist",
)
