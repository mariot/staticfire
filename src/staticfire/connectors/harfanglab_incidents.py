from datetime import UTC, datetime, timedelta

from staticfire.connector_vendors import ConnectorSpec


def _env(alert_types: str, import_threats: bool = False):
    def env(fake) -> dict[str, str]:
        start = (datetime.now(UTC) - timedelta(days=3)).strftime("%Y-%m-%d")
        return {
            "HARFANGLAB_INCIDENTS_URL": "https://tenant.hurukai.io",
            "HARFANGLAB_INCIDENTS_TOKEN": "staticfire-fake-key",
            "HARFANGLAB_INCIDENTS_ALERT_STATUSES": "new,investigating",
            "HARFANGLAB_INCIDENTS_ALERT_TYPES": alert_types,
            "HARFANGLAB_INCIDENTS_IMPORT_THREATS": str(import_threats).lower(),
            "HARFANGLAB_INCIDENTS_IMPORT_START_DATE": start,
        }

    return env


ALERTS = ["/harfanglab/api/data/alert/alert/Alert"]
RULES = {"incident", "indicator", "sighting", "identity", "hostname", "attack-pattern"}

SPECS = [
    ConnectorSpec(
        recipe="harfanglab-incidents",
        connector="external-import/harfanglab-incidents",
        env=_env("yara,sigma"),
        expected_types=RULES | {"relationship:uses", "relationship:related-to"},
        calls=ALERTS + ["/harfanglab/api/data/threat_intelligence/SigmaRule"],
        description="Sigma and YARA alerts become incidents, indicators, sightings and TTPs",
    ),
    ConnectorSpec(
        recipe="harfanglab-incidents-threats",
        connector="external-import/harfanglab-incidents",
        env=_env("yara,sigma", import_threats=True),
        expected_types=RULES | {"note"},
        calls=ALERTS + ["/harfanglab/api/data/alert/alert/Threat"],
        description="threats become case incidents with their alerts and analyst note",
    ),
    ConnectorSpec(
        recipe="harfanglab-incidents-ioc",
        connector="external-import/harfanglab-incidents",
        env=_env("ioc"),
        expected_types=RULES | {"ipv4-addr", "url", "file"},
        calls=ALERTS + ["/harfanglab/api/data/threat_intelligence/IOCRule"],
        description="IOC alerts (hash, filename, IP, domain, URL) become incidents and indicators",
    ),
]
