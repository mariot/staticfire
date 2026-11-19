import shutil
import time
import uuid

import httpx

from staticfire import config
from staticfire.connector_vendors import ConnectorSpec

BACKUP_DIR = config.STATE_DIR / "backup-files-out"
OFAPI = "http://127.0.0.1:8000"


def _env(fake) -> dict[str, str]:
    shutil.rmtree(BACKUP_DIR, ignore_errors=True)
    BACKUP_DIR.mkdir(parents=True)
    return {"BACKUP_PROTOCOL": "local", "BACKUP_PATH": str(BACKUP_DIR)}


def _stream(cti) -> list[str]:
    """Create an indicator and an observable, wait for their backup files (the connector writes
    to disk, not to an API) and post those files to ofapi, where the recipe looks for them."""
    token = uuid.uuid4().hex[:8]
    domain = f"sf-{token}.example.com"
    ip = f"198.51.{int(token[:2], 16) % 256}.{int(token[2:4], 16) % 254 + 1}"
    cti.create_indicator(f"staticfire {domain}", f"[domain-name:value = '{domain}']", "Domain-Name")
    cti.create_observable("IPv4-Addr", ip)
    deadline = time.time() + 120
    posted: set[str] = set()
    while time.time() < deadline and len(posted) < 2:
        for path in (BACKUP_DIR / "opencti_data").glob("*/*.json"):
            content = path.read_text()
            for marker in (domain, ip):
                if marker in content and marker not in posted:
                    posted.add(marker)
                    httpx.post(
                        f"{OFAPI}/backup-files/files", json={"name": path.name, "content": content}
                    )
        time.sleep(2)
    return [domain, ip]


SPEC = ConnectorSpec(
    recipe="backup-files",
    connector="stream/backup-files",
    env=_env,
    stream=_stream,
    calls=["/backup-files/files"],
    description="created objects are written as JSON backup files under the backup directory",
)
