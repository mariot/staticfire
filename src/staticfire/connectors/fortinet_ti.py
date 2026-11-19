import json
import os
from pathlib import Path

from staticfire.connector_vendors import ConnectorSpec

KNOWN_PATTERN = "[ipv4-addr:value = '198.51.100.10']"


def _env(fake) -> dict[str, str]:
    """The connector only imports what is new compared with the previous day's feed, which it
    keeps in a file of its working directory: its first run imports the author alone. The
    previous day's feed is put there, as a run of the day before would have left it."""
    root = Path(os.environ.get("STATICFIRE_CONNECTORS_DIR", Path.home() / "GitHub" / "connectors"))
    old = root / "external-import" / "fortinet-ti" / "src" / "fortinet_ioc_old.json"
    old.write_text(json.dumps({"type": "bundle", "objects": [{"pattern": KNOWN_PATTERN}]}))
    return {"FORTINET_API_KEY": "staticfire-fake-key"}


SPEC = ConnectorSpec(
    recipe="fortinet-ti",
    connector="external-import/fortinet-ti",
    env=_env,
    expected_types={"ipv4-addr", "url", "indicator", "relationship:based-on"},
    calls=["/fortinet-ti/v1/cti/feed/stix2", "/fortinet-ti/v1/cti/feed/download/"],
    description="the new URL and address indicators of the feed (those absent from the "
    "previous day's file) become observables and indicators",
)
