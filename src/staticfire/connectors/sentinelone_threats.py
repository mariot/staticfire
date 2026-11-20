from staticfire import config
from staticfire.connector_vendors import ConnectorSpec

# libmagic is a system library the machine may lack, and python-magic does not load without it:
# a module of the same name, using the file(1) command, stands in for it
MAGIC_SHIM = """\
import subprocess


def from_buffer(buffer, mime=False):
    option = "--mime-type" if mime else "--brief"
    out = subprocess.run(["/usr/bin/file", option, "-b", "-"], input=buffer, capture_output=True)
    return out.stdout.decode().strip()


def from_file(path, mime=False):
    with open(path, "rb") as stream:
        return from_buffer(stream.read(), mime)
"""
SHIM_DIR = config.STATE_DIR / "shims" / "sentinelone-threats"


def _env(fake) -> dict[str, str]:
    SHIM_DIR.mkdir(parents=True, exist_ok=True)
    (SHIM_DIR / "magic.py").write_text(MAGIC_SHIM)
    return {
        "PYTHONPATH": str(SHIM_DIR),
        "SENTINELONE_THREATS_BASE_URL": "https://staticfire.sentinelone.net",
        "SENTINELONE_THREATS_API_TOKEN": "staticfire-fake-key",
    }


SPEC = ConnectorSpec(
    recipe="sentinelone-threats",
    connector="external-import/sentinelone-threats",
    env=_env,
    calls=["/sentinelone-console/web/api/v2.1/threats"],
    opens_work=False,
    expected_types={"artifact"},
    description="threats are downloaded (password protected ZIP) and uploaded as artifacts "
    "with classification and extension labels, through the API: the connector opens no work",
)
