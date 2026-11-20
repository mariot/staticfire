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
SHIM_DIR = config.STATE_DIR / "shims" / "shadowserver"


def _env(fake) -> dict[str, str]:
    SHIM_DIR.mkdir(parents=True, exist_ok=True)
    (SHIM_DIR / "magic.py").write_text(MAGIC_SHIM)
    return {
        "PYTHONPATH": str(SHIM_DIR),
        "SHADOWSERVER_API_KEY": "staticfire-fake-key",
        "SHADOWSERVER_API_SECRET": "staticfire-fake-secret",
        "SHADOWSERVER_INITIAL_LOOKBACK": "1",
        "SHADOWSERVER_CREATE_INCIDENT": "true",
    }


SPEC = ConnectorSpec(
    recipe="shadowserver",
    connector="external-import/shadowserver",
    env=_env,
    expected_types={
        "artifact",
        "report",
        "note",
        "observed-data",
        "ipv4-addr",
        "domain-name",
        "autonomous-system",
        "x509-certificate",
        "vulnerability",
        "case-incident",
    },
    calls=["/shadowserver/api2/reports/list", "/shadowserver/"],
    description="the HMAC signed report list of two days and their CSV downloads become "
    "artifacts, observables, observed data, a report, notes and a case incident per report",
)
