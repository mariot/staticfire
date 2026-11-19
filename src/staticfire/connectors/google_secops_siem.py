import subprocess
import tempfile
from pathlib import Path

from staticfire.connector_vendors import ConnectorSpec


def _private_key() -> str:
    """A throw-away RSA key (PKCS8 PEM): the service account JWT is signed locally."""
    with tempfile.TemporaryDirectory() as tmp:
        key = Path(tmp, "key.pem")
        subprocess.run(
            ["openssl", "genpkey", "-algorithm", "RSA", "-out", str(key)],
            check=True,
            capture_output=True,
        )
        return key.read_text()


def _env(fake) -> dict[str, str]:
    return {
        "SECOPS_SIEM_PROJECT_REGION": "us",
        "SECOPS_SIEM_PROJECT_ID": "staticfire-project",
        "SECOPS_SIEM_PROJECT_INSTANCE": "7c3b9d52-1f0e-4a8b-9c6d-2e5f4a3b1c0d",
        "SECOPS_SIEM_PRIVATE_KEY": _private_key(),
        "SECOPS_SIEM_PRIVATE_KEY_ID": "0123456789abcdef0123456789abcdef01234567",
        "SECOPS_SIEM_CLIENT_EMAIL": "opencti@staticfire-project.iam.gserviceaccount.com",
        "SECOPS_SIEM_CLIENT_ID": "112233445566778899001",
        "SECOPS_SIEM_CLIENT_CERT_URL": "https://www.googleapis.com/robot/v1/metadata/x509/"
        "opencti%40staticfire-project.iam.gserviceaccount.com",
    }


SPEC = ConnectorSpec(
    recipe="google-secops-siem",
    connector="stream/google-secops-siem",
    env=_env,
    calls=["/google-identity/token", "/google-secops/v1alpha"],
    description="created indicators are imported as UDM entities into the SecOps instance "
    "(service account token, then entities:import)",
)
