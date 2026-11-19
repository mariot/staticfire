import uuid

from staticfire.connector_vendors import ConnectorSpec

DESCRIPTION = "staticfire misp-intel report"
# The shared stream carries the reports of every other test, some holding objects the MISP
# conversion cannot take: the test follows its own stream, limited to its report.
FILTERS = {
    "mode": "and",
    "filters": [
        {"key": ["entity_type"], "values": ["Report"], "operator": "eq", "mode": "or"},
        {"key": ["description"], "values": [DESCRIPTION], "operator": "eq", "mode": "or"},
    ],
    "filterGroups": [],
}


def _report(cti) -> list[str]:
    """A report on a new domain and a new IPv4 address: the container the connector exports."""
    token = uuid.uuid4().hex
    domain = f"sf-{token[:8]}.example.com"
    ip = f"198.51.{int(token[8:10], 16) % 256}.{int(token[10:12], 16) % 254 + 1}"
    observables = [
        cti.create_observable("Domain-Name", domain)["id"],
        cti.create_observable("IPv4-Addr", ip)["id"],
    ]
    cti.graphql(
        """mutation ($input: ReportAddInput!) { reportAdd(input: $input) { id } }""",
        {
            "input": {
                "name": f"staticfire misp-intel {token[:8]}",
                "published": "2026-01-01T00:00:00.000Z",
                "description": DESCRIPTION,
                "objects": observables,
            }
        },
    )
    return [domain, ip]


SPEC = ConnectorSpec(
    recipe="misp-intel",
    connector="stream/misp-intel",
    env=lambda fake: {
        "MISP_URL": "https://misp.staticfire.test",
        "MISP_API_KEY": "staticfire-fake-key",
    },
    stream_filters=FILTERS,
    stream=_report,
    calls=["/misp/events/add"],
    description="a report with its observables is created as a MISP event (attributes) and "
    "linked back to the report through an external reference (own stream limited to the "
    "test's report)",
)
