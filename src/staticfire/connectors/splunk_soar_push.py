import uuid

from staticfire.connector_vendors import ConnectorSpec

NAME_PREFIX = "staticfire soar push"
MARKER = "staticfire-soar-push-test"
# The connector only handles incidents and containers: its own stream keeps the test's reports
FILTERS = {
    "mode": "and",
    "filters": [
        {"key": ["entity_type"], "values": ["Report"], "operator": "eq", "mode": "or"},
        {"key": ["description"], "values": [MARKER], "operator": "contains", "mode": "or"},
    ],
    "filterGroups": [],
}


def _report(cti) -> list[str]:
    """A report holding an address and a domain indicator; its name is the marker."""
    token = uuid.uuid4().hex[:8]
    ip = cti.create_observable("IPv4-Addr", f"198.51.100.{int(token[:2], 16) % 254 + 1}")
    domain = f"sf-{token}.example.com"
    indicator = cti.create_indicator(
        f"staticfire {domain}", f"[domain-name:value = '{domain}']", "Domain-Name"
    )
    name = f"{NAME_PREFIX} {token}"
    cti.graphql(
        """mutation ($input: ReportAddInput!) { reportAdd(input: $input) { id } }""",
        {
            "input": {
                "name": name,
                "published": "2026-01-01T00:00:00.000Z",
                "description": MARKER,
                "objects": [ip["id"], indicator["id"]],
            }
        },
    )
    return [name]


SPEC = ConnectorSpec(
    recipe="splunk-soar-push",
    connector="stream/splunk-soar-push",
    env=lambda fake: {
        "SPLUNK_SOAR_URL": "https://soar.staticfire.test",
        "SPLUNK_SOAR_API_TOKEN": "staticfire-fake-token",
    },
    stream_filters=FILTERS,
    stream=_report,
    calls=["/splunk-soar/rest/container"],
    description="a report becomes a SOAR case (container) with artifacts for its observable "
    "and indicator (own stream limited to the test's reports)",
)
