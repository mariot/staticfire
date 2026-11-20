import base64
import json
import uuid

from staticfire.connector_vendors import ConnectorSpec

NAME_PREFIX = "staticfire logrhythm"
DOMAIN = "logrhythm.staticfire.example.com"
# The connector builds its JSON requests by pasting values in a template: a name with a
# backslash or a quote, in the changes of the whole platform the shared test stream carries, makes
# it exit. The test follows its own stream, limited to the indicators it creates.
FILTERS = {
    "mode": "and",
    "filters": [
        {"key": ["entity_type"], "values": ["Indicator"], "operator": "eq", "mode": "or"},
        {"key": ["pattern"], "values": [DOMAIN], "operator": "contains", "mode": "or"},
    ],
    "filterGroups": [],
}


def _token() -> str:
    """A JWT-shaped token: the connector reads the API user id from its payload."""
    claims = base64.urlsafe_b64encode(json.dumps({"uid": 7}).encode()).decode().rstrip("=")
    return f"eyJhbGciOiJub25lIn0.{claims}.c2ln"


def _domain_indicator(cti) -> list[str]:
    domain = f"sf-{uuid.uuid4().hex[:8]}.{DOMAIN}"
    cti.create_indicator(
        f"{NAME_PREFIX} {domain}", f"[domain-name:value = '{domain}']", "Domain-Name"
    )
    return [domain]


SPEC = ConnectorSpec(
    recipe="logrhythm-cti",
    connector="stream/logrhythm",
    env=lambda fake: {
        "LOGRHYTHM_URL": "https://logrhythm.staticfire.test:8501/lr-admin-api",
        "LOGRHYTHM_TOKEN": _token(),
        "LOGRHYTHM_entity": "staticfire",
        "LOGRHYTHM_LIST_NAME": "opencti",
        "CONNECTOR_CONSUMER_COUNT": "2",
        "LOGRHYTHM_IGNORE_TYPES": "label,marking-definition,identity,organization",
    },
    stream_filters=FILTERS,
    stream=_domain_indicator,
    calls=["/logrhythm/lr-admin-api/lists/"],
    description="an indicator's value is added to a LogRhythm list named after its observable "
    "type (own stream limited to the test's indicators)",
)
