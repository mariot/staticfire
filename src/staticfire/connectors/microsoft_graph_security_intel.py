import uuid

from staticfire.connector_vendors import ConnectorSpec

SUFFIX = "graph.staticfire.example.com"
# The connector follows its own stream, limited to the indicator and the scored observable
# (score 71) the test creates: the platform's other changes are not its concern.
FILTERS = {
    "mode": "or",
    "filters": [],
    "filterGroups": [
        {
            "mode": "and",
            "filters": [
                {"key": ["entity_type"], "values": ["Indicator"], "operator": "eq", "mode": "or"},
                {"key": ["pattern"], "values": [SUFFIX], "operator": "contains", "mode": "or"},
            ],
            "filterGroups": [],
        },
        {
            "mode": "and",
            "filters": [
                {"key": ["entity_type"], "values": ["Domain-Name"], "operator": "eq", "mode": "or"},
                {"key": ["x_opencti_score"], "values": ["71"], "operator": "eq", "mode": "or"},
            ],
            "filterGroups": [],
        },
    ],
}


def _objects(cti) -> list[str]:
    """An indicator on a new domain and a scored observable on another one."""
    token = uuid.uuid4().hex[:8]
    indicator_domain = f"sf-{token}-ioc.{SUFFIX}"
    observable_domain = f"sf-{token}-obs.{SUFFIX}"
    cti.create_indicator(
        f"staticfire {indicator_domain}",
        f"[domain-name:value = '{indicator_domain}']",
        "Domain-Name",
    )
    cti.graphql(
        """mutation ($value: String!) { stixCyberObservableAdd(type: "Domain-Name",
             x_opencti_score: 71, DomainName: { value: $value }) { id } }""",
        {"value": observable_domain},
    )
    return [indicator_domain, observable_domain]


SPEC = ConnectorSpec(
    recipe="microsoft-graph-security-intel",
    connector="stream/microsoft-graph-security-intel",
    env=lambda fake: {
        "MICROSOFT_GRAPH_SECURITY_INTEL_TENANT_ID": "0b9a2c6e-6d1f-4c0e-9a57-3f2f1d7c8e11",
        "MICROSOFT_GRAPH_SECURITY_INTEL_CLIENT_ID": "5c1d7e2a-33b4-4e0a-8f6d-9a1b2c3d4e5f",
        "MICROSOFT_GRAPH_SECURITY_INTEL_CLIENT_SECRET": "staticfire-fake-secret",
    },
    stream_filters=FILTERS,
    stream=_objects,
    calls=["/microsoft-graph/beta/security/tiIndicators"],
    description="a new indicator and a scored observable become Graph tiIndicators (domain "
    "name, threat type, action, expiration), linked back through an external reference (own "
    "stream limited to the test's objects)",
)
