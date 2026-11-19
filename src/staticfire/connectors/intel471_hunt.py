import uuid
from pathlib import Path

from staticfire.connector_vendors import ConnectorSpec

# The connector caches the hunts it pushed: its default path (a container's) is not writable
CACHE = Path.home() / ".local/state/staticfire/runs/connector-intel471-hunt-cache/cache.json"


def _intrusion_set(cti) -> str:
    return cti.create_intrusion_set(f"StaticFire Bear {uuid.uuid4().hex[:6]}")["id"]


SPEC = ConnectorSpec(
    recipe="intel471-hunt",
    connector="internal-enrichment/intel471-hunt",
    env=lambda fake: {
        "HUNTER_API_KEY": "staticfire-fake-key",
        "HUNTER_CACHE_PATH": str(CACHE),
    },
    enrich=_intrusion_set,
    expected_types={
        "report",
        "indicator",
        "note",
        "attack-pattern",
        "campaign",
        "malware",
        "tool",
        "vulnerability",
        "identity",
        "location",
        "intrusion-set",
        "relationship:indicates",
        "relationship:uses",
    },
    calls=["/hunter/es/query"],
    description="hunt packages found for an intrusion set become reports with a sigma "
    "indicator, notes and the techniques, campaigns, malware and sectors they name",
)
