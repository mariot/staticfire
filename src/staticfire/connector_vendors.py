"""OpenCTI connectors: how to run each one against ofapi and what its run must produce.

One module per connector in ``staticfire/connectors/`` exposes ``SPEC`` (or ``SPECS``). The
connector's family (its directory in the connectors repository) decides how it is exercised:

* external-import: it runs once; its work must complete without error and ingest the expected
  types.
* internal-enrichment: an observable is created and its enrichment asked from the connector.
* internal-import-file: a file is uploaded and its import asked from the connector.
* internal-export-file: objects are exported to the connector's format.
* stream: the connector listens to a live stream; objects are created and the connector must
  call its vendor (``calls``).

By default every HTTP(S) request of the connector goes through the proxy to ofapi, where the
vendor module declaring that host answers (``HOSTS`` in ofapi's ``app/vendors/<vendor>.py``), so
a hardcoded vendor URL is not a problem. What ingestion produced is read back by creator: each
connector runs under its own OpenCTI service account.
"""

from __future__ import annotations

import importlib
import json
import pkgutil
import re
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from staticfire.fakes import Ofapi
from staticfire.vendors import Rule

FAMILIES = (
    "external-import",
    "internal-enrichment",
    "internal-import-file",
    "internal-export-file",
    "stream",
)


@dataclass
class ConnectorSpec:
    recipe: str
    connector: str  # "<family>/<name>" in the connectors repository
    env: Callable[[Ofapi], dict[str, str]] = lambda fake: {}
    rules: Callable[[Ofapi], list[Rule]] = lambda fake: []
    # STIX types the connector must send ("relationship:<type>" for a kind of relationship)
    expected_types: set[str] = field(default_factory=set)
    min_elements: int = 1
    # ofapi path prefixes the connector must have called (after the proxy's host rewriting)
    calls: list[str] = field(default_factory=list)
    # internal-enrichment: (observable type, value) to create, or a function of the OpenCTI
    # client returning the id of the object to enrich
    enrich: tuple[str, str] | Callable[[Any], str] | None = None
    # internal-import-file: (file name, ofapi path serving its content, mime type)
    import_file: tuple[str, str, str] | None = None
    # internal-export-file: the export format (mime type) and whether it exports a "list" of
    # objects or one "entity"; export_object makes the object (OpenCTI client -> (id, type)),
    # an indicator by default
    export: tuple[str, str] | None = None
    export_object: Callable[[Any], tuple[str, str]] | None = None
    # stream: creates objects once the connector listens and returns values unique to them,
    # which must show in what the vendor receives (by default an indicator on a new domain
    # and a new IPv4 observable)
    stream: Callable[[Any], list[str]] | None = None
    # Send the connector's HTTP(S) through the proxy (off for clients ignoring proxies, which
    # then need their vendor URL pointed at ofapi in ``env``)
    proxy: bool = True
    # Why the connector cannot be exercised offline; the recipe then only reports it
    blocked: str = ""
    timeout: float = 300
    description: str = ""

    @property
    def family(self) -> str:
        return self.connector.split("/", 1)[0]


SKIPPED_DEFAULTS = ("OPENCTI_", "CONNECTOR_ID", "CONNECTOR_NAME", "CONNECTOR_LOG_LEVEL")


def compose_defaults(connector_dir: Path) -> dict[str, str]:
    """The settings of the connector's docker-compose.yml that are not placeholders.

    Connectors without a config schema read config.yml, which a test does not have: their
    compose file holds the values they need, such as the scope of a file connector.
    """
    compose = connector_dir / "docker-compose.yml"
    if not compose.exists():
        return {}
    try:
        services = (yaml.safe_load(compose.read_text()) or {}).get("services") or {}
    except yaml.YAMLError:
        return {}
    defaults = {}
    for service in services.values():
        environment = (service or {}).get("environment") or {}
        if isinstance(environment, list):
            environment = dict(item.split("=", 1) for item in environment if "=" in str(item))
        for name, value in environment.items():
            value = "" if value is None else str(value)
            if isinstance(environment.get(name), bool):
                value = value.lower()
            # ${VAR:-default}: the default (itself maybe ${OTHER:-...}), ${VAR}: none
            while substitution := re.fullmatch(r"\$\{\w+(?::?-(.*))?\}", value):
                value = substitution.group(1) or ""
            if name.startswith(SKIPPED_DEFAULTS) or not value or "changeme" in value.lower():
                continue
            defaults[name] = value
    return defaults


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


# spec module -> why it could not be imported
BROKEN: dict[str, str] = {}


def _discover() -> dict[str, ConnectorSpec]:
    from staticfire import connectors

    specs: dict[str, ConnectorSpec] = {}
    for info in sorted(pkgutil.iter_modules(connectors.__path__), key=lambda m: m.name):
        if info.name.startswith("_"):
            continue
        try:
            module = importlib.import_module(f"{connectors.__name__}.{info.name}")
        except Exception as err:  # one broken spec must not hide the others
            BROKEN[info.name] = f"{type(err).__name__}: {err}"
            continue
        found = getattr(module, "SPECS", None) or [getattr(module, "SPEC", None)]
        for spec in filter(None, found):
            if spec.recipe in specs:
                raise ValueError(f"Two connector specs named {spec.recipe}")
            specs[spec.recipe] = spec
    return specs


SPECS: dict[str, ConnectorSpec] = _discover()
