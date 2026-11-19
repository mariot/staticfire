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
    prefix = "GOOGLE_SECOPS_SIEM_INCIDENTS_"
    return {
        # The connector's aiohttp client ignores the proxy: it builds
        # https://<region>-<base host>/v1alpha/..., so the region carries ofapi's address
        prefix + "BASE_URL": "https://chronicle.googleapis.com",
        prefix + "PROJECT_REGION": fake.url("google-secops/r"),
        prefix + "PROJECT_ID": "staticfire-project",
        prefix + "PROJECT_INSTANCE": "7c3b9d52-1f0e-4a8b-9c6d-2e5f4a3b1c0d",
        prefix + "PRIVATE_KEY": _private_key(),
        prefix + "PRIVATE_KEY_ID": "0123456789abcdef0123456789abcdef01234567",
        prefix + "CLIENT_EMAIL": "opencti@staticfire-project.iam.gserviceaccount.com",
        prefix + "CLIENT_ID": "112233445566778899001",
        prefix + "CLIENT_CERT_URL": "https://www.googleapis.com/robot/v1/metadata/x509/"
        "opencti%40staticfire-project.iam.gserviceaccount.com",
        prefix + "TOKEN_URI": fake.http_url("google-identity") + "/token",
    }


SPEC = ConnectorSpec(
    recipe="google-secops-siem-incidents",
    connector="external-import/google-secops-siem-incidents",
    env=_env,
    proxy=False,
    expected_types={
        "incident",
        "ipv4-addr",
        "hostname",
        "url",
        "user-account",
        "email-addr",
        "file",
        "attack-pattern",
        "relationship:related-to",
    },
    calls=["/google-identity/token", "/google-secops/r-chronicle.googleapis.com/v1alpha"],
    description="rule alerts of a SecOps instance (service account token, instance lookup, "
    "legacy alert search) become incidents with their observables and ATT&CK patterns",
)
