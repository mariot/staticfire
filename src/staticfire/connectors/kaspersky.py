from datetime import UTC, datetime

from staticfire.config import STATE_DIR
from staticfire.connector_vendors import ConnectorSpec
from staticfire.fakes import tls_files


def _client_certificate() -> str:
    """The client certificate and key the connector presents, in one PEM file."""
    cert, key = tls_files()
    pem = STATE_DIR / "kaspersky-client.pem"
    pem.write_text(cert.read_text() + key.read_text())
    pem.chmod(0o600)
    return str(pem)


def _env(fake) -> dict[str, str]:
    # the Master IOC and YARA files are fetched on a given ISO weekday: today
    today = str(datetime.now(UTC).isoweekday())
    return {
        "KASPERSKY_USER": "staticfire",
        "KASPERSKY_PASSWORD": "staticfire-fake-key",
        "KASPERSKY_CERTIFICATE_PATH": _client_certificate(),
        "KASPERSKY_MASTER_IOC_FETCH_WEEKDAY": today,
        "KASPERSKY_MASTER_YARA_FETCH_WEEKDAY": today,
    }


SPEC = ConnectorSpec(
    recipe="kaspersky",
    connector="external-import/kaspersky",
    env=_env,
    expected_types={
        "report",
        "intrusion-set",
        "indicator",
        "domain-name",
        "ipv4-addr",
        "location",
        "relationship:targets",
        "relationship:based-on",
        "relationship:indicates",
    },
    calls=[
        "/kaspersky/api/publications/get_list",
        "/kaspersky/api/publications/get_one",
        "/kaspersky/api/publications/get_master_ioc",
        "/kaspersky/api/publications/get_master_yara",
    ],
    description="publications (PDF report, OpenIOC and YARA), the Master IOC CSV and the Master "
    "YARA file become reports, intrusion sets, locations, observables and indicators",
)
