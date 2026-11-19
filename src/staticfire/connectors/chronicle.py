import subprocess
import tempfile
from pathlib import Path

from staticfire.connector_vendors import ConnectorSpec


def _private_key() -> str:
    """A throwaway RSA key (PKCS8 PEM, newlines escaped) to sign the service account's JWT."""
    with tempfile.TemporaryDirectory() as tmp:
        key = Path(tmp, "key.pem")
        subprocess.run(
            ["openssl", "genpkey", "-algorithm", "RSA", "-out", str(key)],
            check=True,
            capture_output=True,
        )
        return key.read_text().strip().replace("\n", "\\n")


def _env(fake) -> dict[str, str]:
    return {
        "CHRONICLE_URL": fake.http_url("chronicle"),
        "CHRONICLE_LIST_NAME": "opencti_staticfire",
        "CHRONICLE_IGNORE_TYPES": "marking-definition,identity",
        "CHRONICLE_PROJECT_ID": "staticfire-project",
        "CHRONICLE_PRIVATE_KEY": _private_key(),
        "CHRONICLE_PRIVATE_KEY_ID": "0123456789abcdef0123456789abcdef01234567",
        "CHRONICLE_CLIENT_EMAIL": "opencti@staticfire-project.iam.gserviceaccount.com",
        "CHRONICLE_CLIENT_ID": "112233445566778899001",
        "CHRONICLE_AUTH_URI": "https://accounts.google.com/o/oauth2/auth",
        "CHRONICLE_TOKEN_URI": fake.http_url("chronicle") + "/token",
        "CHRONICLE_AUTH_PROVIDER_CERT": "https://www.googleapis.com/oauth2/v1/certs",
        "CHRONICLE_CLIENT_CERT_URL": "https://www.googleapis.com/robot/v1/metadata/x509/"
        "opencti%40staticfire-project.iam.gserviceaccount.com",
    }


SPEC = ConnectorSpec(
    recipe="chronicle",
    connector="stream/chronicle",
    env=_env,
    proxy=False,
    calls=["/chronicle/v2/lists"],
    description="created objects are appended to a Chronicle reference list (service "
    "account token, read then patch of the list lines)",
)
