import time

from staticfire.connector_vendors import ConnectorSpec
from staticfire.fakes import Proxy

STREAMS = ("indicators", "yara", "cves", "iocs")


def _env(fake) -> dict[str, str]:
    # Intervals are in minutes (the first poll comes one interval after the start) and the
    # history in epoch milliseconds
    since = str(int((time.time() - 3 * 86400) * 1000))
    env = {
        "INTEL471_API_USERNAME": "staticfire@example.com",
        "INTEL471_API_KEY": "fake-key",
        # The Titan client (urllib3) ignores the proxy variables: its own setting is used
        "INTEL471_PROXY": Proxy().url,
    }
    for stream in STREAMS:
        env[f"INTEL471_INTERVAL_{stream.upper()}"] = "1"
        env[f"INTEL471_INITIAL_HISTORY_{stream.upper()}"] = since
    return env


SPEC = ConnectorSpec(
    recipe="intel471",
    connector="external-import/intel471",
    env=_env,
    expected_types={
        "indicator",
        "malware",
        "vulnerability",
        "software",
        "ipv4-addr",
        "url",
        "domain-name",
        "file",
        "relationship:indicates",
        "relationship:based-on",
        "relationship:has",
    },
    calls=[
        "/intel471/v1/indicators/stream",
        "/intel471/v1/yara",
        "/intel471/v1/cve/reports",
        "/intel471/v1/iocs",
    ],
    description="Titan indicators, YARA rules, CVE reports and IOCs become indicators with "
    "their observables and malware, and vulnerabilities",
)
