from staticfire.connector_vendors import ConnectorSpec
from staticfire.connectors import imap_server


def _env(fake) -> dict[str, str]:
    return {
        "EMAIL_INTEL_IMAP_HOST": "127.0.0.1",
        "EMAIL_INTEL_IMAP_PORT": str(imap_server.ensure(fake)),
        "EMAIL_INTEL_IMAP_USERNAME": "soc@staticfire.test",
        "EMAIL_INTEL_IMAP_PASSWORD": "staticfire-fake-key",
    }


SPEC = ConnectorSpec(
    recipe="email-intel-imap",
    connector="external-import/email-intel-imap",
    env=_env,
    expected_types={"report"},
    calls=["/mailbox/messages"],
    description="a local IMAP server (TLS) serves ofapi's mailbox: each recent email becomes a "
    "report with its PDF/CSV/text attachments (uploaded as files, not in the bundles)",
)
