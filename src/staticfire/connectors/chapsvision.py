import base64
import subprocess
import tempfile
from datetime import UTC, datetime, timedelta
from pathlib import Path

from staticfire.connector_vendors import ConnectorSpec


def _client_certificate() -> tuple[str, str]:
    """A throwaway client certificate and key (PEM, base64) for the connector's mutual TLS."""
    with tempfile.TemporaryDirectory() as tmp:
        key, crt = Path(tmp, "key.pem"), Path(tmp, "crt.pem")
        subprocess.run(
            ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "2"]
            + ["-subj", "/CN=staticfire", "-keyout", str(key), "-out", str(crt)],
            check=True,
            capture_output=True,
        )
        return (
            base64.b64encode(crt.read_bytes()).decode(),
            base64.b64encode(key.read_bytes()).decode(),
        )


def _env(fake) -> dict[str, str]:
    certificate, key = _client_certificate()
    # one full day to process (one query, then the connector waits a minute)
    start = datetime.now(UTC) - timedelta(hours=30)
    return {
        "CHAPSVISION_CERTIFICATE": certificate,
        "CHAPSVISION_KEY": key,
        "CHAPSVISION_QUERY_PARAMETER": "_params",
        "CHAPSVISION_START_DATE": start.isoformat(),
    }


SPEC = ConnectorSpec(
    recipe="chapsvision",
    connector="external-import/chapsvision",
    env=_env,
    expected_types={"channel", "media-content", "relationship:publishes", "report"},
    calls=["/chapsvision/mcapi/documents"],
    description="micro blogging, messaging and website documents become channels, media "
    "content and a daily digest report",
)
