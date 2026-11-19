import time

from staticfire.connector_vendors import ConnectorSpec
from staticfire.fakes import Proxy

STREAMS = ("indicators", "yara", "cves")


def _env(fake) -> dict[str, str | None]:
    # Intervals are in minutes (the first poll comes one interval after the start) and the
    # history in epoch milliseconds
    since = str(int((time.time() - 3 * 86400) * 1000))
    env = {
        "INTEL471_API_USERNAME": "staticfire@example.com",
        "INTEL471_API_KEY": "fake-key",
        "INTEL471_BACKEND": "titan",
        # The Titan client (urllib3) ignores the proxy variables: its own setting is used
        "INTEL471_PROXY": Proxy().url,
        # the report streams are not faked
        "INTEL471_INTERVAL_REPORTS": "0",
        # its settings type this one as None ("do not use"): any value stops it at startup
        "CONNECTOR_DURATION_PERIOD": None,
    }
    for stream in STREAMS:
        env[f"INTEL471_INTERVAL_{stream.upper()}"] = "1"
        env[f"INTEL471_INITIAL_HISTORY_{stream.upper()}"] = since
    return env


SPEC = ConnectorSpec(
    recipe="intel471_v2",
    connector="external-import/intel471_v2",
    env=_env,
    expected_types={
        "indicator",
        "malware",
        "vulnerability",
        "software",
        "ipv4-addr",
        "url",
        "file",
        "relationship:indicates",
        "relationship:based-on",
        "relationship:has",
    },
    calls=[
        "/intel471/v1/indicators/stream",
        "/intel471/v1/yara",
        "/intel471/v1/cve/reports",
    ],
    description="Titan backend: indicators, YARA rules and CVE reports become indicators with "
    "their observables and malware, and vulnerabilities (report streams off)",
)
