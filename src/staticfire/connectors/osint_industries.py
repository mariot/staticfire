import uuid

from staticfire.connector_vendors import ConnectorSpec


def _new_email(cti) -> str:
    return cti.create_observable("Email-Addr", f"sf-{uuid.uuid4().hex[:8]}@example.com")["id"]


SPEC = ConnectorSpec(
    recipe="osint-industries",
    connector="internal-enrichment/osint-industries",
    env=lambda fake: {"OSINT_INDUSTRIES_API_KEY": "staticfire-fake-key"},
    enrich=_new_email,
    expected_types={
        "user-account",
        "email-addr",
        "url",
        "phone-number",
        "cryptocurrency-wallet",
        "note",
        "relationship:related-to",
    },
    calls=["/osint-industries/v2/request"],
    description="an email address gets the accounts found by each module (with their emails, "
    "profile URLs, phone and wallet), summary and breach notes; the HTML report is attached "
    "as a file",
)
