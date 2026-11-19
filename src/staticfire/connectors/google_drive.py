import subprocess

from staticfire.connector_vendors import ConnectorSpec


def _private_key() -> str:
    """A throw-away RSA key: the service account JWT is signed locally before it is sent."""
    return subprocess.run(
        ["openssl", "genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048"],
        capture_output=True,
        text=True,
        check=True,
    ).stdout


SPEC = ConnectorSpec(
    recipe="google-drive",
    connector="external-import/google-drive",
    env=lambda fake: {
        "GOOGLE_DRIVE_PROJECT_ID": "staticfire",
        "GOOGLE_DRIVE_PRIVATE_KEY_ID": "staticfire-key-id",
        "GOOGLE_DRIVE_PRIVATE_KEY": _private_key(),
        "GOOGLE_DRIVE_CLIENT_EMAIL": "staticfire@staticfire.iam.gserviceaccount.com",
        "GOOGLE_DRIVE_CLIENT_ID": "100000000000000000000",
        "GOOGLE_DRIVE_CLIENT_X509_CERT_URL": "https://www.googleapis.com/robot/v1/metadata/x509/x",
        "GOOGLE_DRIVE_FOLDER_NAME": "Threat reports",
        "GOOGLE_DRIVE_REPORT_AUTHOR": "Staticfire Drive",
    },
    expected_types={"report"},
    calls=["/google-identity/token", "/google-drive/drive/v3/files"],
    description="a service account lists a Drive folder: its PDF and Word files become reports "
    "with the file attached, the PNG is ignored",
)
