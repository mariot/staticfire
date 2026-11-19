from staticfire.connector_vendors import ConnectorSpec
from staticfire.connectors import imap_server


def _env(fake) -> dict[str, str]:
    return {
        "EMAIL_CASES_PROTOCOL": "imap",
        "EMAIL_CASES_IMAP_HOST": "127.0.0.1",
        "EMAIL_CASES_IMAP_PORT": str(imap_server.ensure(fake)),
        "EMAIL_CASES_IMAP_USERNAME": "soc@staticfire.test",
        "EMAIL_CASES_IMAP_PASSWORD": "staticfire-fake-key",
        "EMAIL_CASES_SENDER_ADDRESS": "alerts@example.com",
        "EMAIL_CASES_LABELS": "staticfire,email",
    }


# The connector creates its cases and uploads their attachments through the API: no bundle
SPEC = ConnectorSpec(
    recipe="email-cases-importer",
    connector="external-import/email-cases-importer",
    env=_env,
    min_elements=0,
    calls=["/mailbox/messages"],
    description="a local IMAP server (TLS) serves ofapi's mailbox: the emails of one sender "
    "become incident cases (threaded replies appended, attachments uploaded); cases are made "
    "through the API, so no bundle is checked",
)
