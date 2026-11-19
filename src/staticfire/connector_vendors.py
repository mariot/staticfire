"""OpenCTI connectors: how to point each one at ofapi and what its run must produce in OpenCTI.

External-import connectors are judged on their *works*: a run completes without error, and the
elements it touched include the entity types the fake data implies. Enrichment connectors are
asked to enrich an observable created for the test.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

from staticfire.fakes import Ofapi
from staticfire.vendors import Rule


@dataclass
class ConnectorSpec:
    recipe: str
    connector: str  # "<family>/<name>" in the connectors repository
    env: Callable[[Ofapi], dict[str, str]]
    rules: Callable[[Ofapi], list[Rule]] = lambda fake: []
    # Entity types the run must have touched (Indicator, IPv4-Addr, Malware, relationship...)
    expected_types: set[str] = field(default_factory=set)
    min_elements: int = 1
    # Path prefixes the connector must have called on the fake
    calls: list[str] = field(default_factory=list)
    # Enrichment connectors: (observable type, value) to create and ask enrichment for
    enrich: tuple[str, str] | None = None
    timeout: float = 300
    description: str = ""


def schema_placeholders(connector_dir: Path, provided: dict[str, str]) -> dict[str, str]:
    """A placeholder for every required setting the spec does not give (from the config schema)."""
    schema_file = connector_dir / "__metadata__" / "connector_config_schema.json"
    if not schema_file.exists():
        return {}
    schema = json.loads(schema_file.read_text())
    placeholders = {}
    for name in schema.get("required", []):
        if name in provided or name.startswith("OPENCTI_"):
            continue
        prop = schema.get("properties", {}).get(name, {})
        kind = prop.get("type")
        if prop.get("enum"):
            value = str(prop["enum"][0])
        elif kind == "integer":
            value = "1"
        elif kind == "boolean":
            value = "false"
        elif kind == "array":
            value = "staticfire"
        else:
            value = "staticfire-placeholder"
        placeholders[name] = value
    return placeholders


HUNT_IO = ConnectorSpec(
    recipe="hunt-io",
    connector="external-import/hunt-io",
    env=lambda fake: {
        "HUNT_IO_API_BASE_URL": fake.http_url("hunt-io/feeds/c2"),
        "HUNT_IO_API_KEY": "staticfire-fake-key",
    },
    expected_types={"IPv4-Addr", "Indicator"},
    calls=["/hunt-io/feeds/c2"],
    description="the C2 feed (gzip JSON lines) becomes indicators and infrastructure",
)

SPECS: dict[str, ConnectorSpec] = {spec.recipe: spec for spec in [HUNT_IO]}
