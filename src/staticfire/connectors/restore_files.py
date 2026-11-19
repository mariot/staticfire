import json
import shutil

from staticfire import config
from staticfire.connector_vendors import ConnectorSpec

BACKUP_DIR = config.STATE_DIR / "restore-files-in"


def _env(fake) -> dict[str, str]:
    """Lay out the backup tree ofapi serves (the format of the backup-files connector)."""
    shutil.rmtree(BACKUP_DIR, ignore_errors=True)
    tree = fake.http.get("/restore-files/backup").raise_for_status().json()
    for name, content in tree.items():
        path = BACKUP_DIR / "opencti_data" / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(content))
    return {"BACKUP_PROTOCOL": "local", "BACKUP_PATH": str(BACKUP_DIR)}


SPEC = ConnectorSpec(
    recipe="restore-files",
    connector="external-import/restore-files",
    env=_env,
    expected_types={
        "report",
        "intrusion-set",
        "malware",
        "attack-pattern",
        "indicator",
        "domain-name",
        "identity",
        "relationship:uses",
        "relationship:indicates",
    },
    description="a two-run backup directory is restored; the older run's references (author, "
    "technique, indicator) are resolved from the newer run (no API is called)",
)
