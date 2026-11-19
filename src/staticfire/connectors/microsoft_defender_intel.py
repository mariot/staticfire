import uuid

from staticfire.connector_vendors import ConnectorSpec

SUFFIX = "defender.staticfire.example.com"
# The shared stream carries the whole platform: observables without a score make the
# connector fail, and e-mail addresses are posted with an empty body. The test follows its
# own stream, limited to the indicator and the observable it creates.
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
                {"key": ["x_opencti_score"], "values": ["73"], "operator": "eq", "mode": "or"},
            ],
            "filterGroups": [],
        },
    ],
}


def _objects(cti) -> list[str]:
    """An indicator on a new domain and a scored observable (score 73) on another one."""
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
             x_opencti_score: 73, DomainName: { value: $value }) { id } }""",
        {"value": observable_domain},
    )
    return [indicator_domain, observable_domain]


ENV = {
    "MICROSOFT_DEFENDER_INTEL_TENANT_ID": "0b9a2c6e-6d1f-4c0e-9a57-3f2f1d7c8e11",
    "MICROSOFT_DEFENDER_INTEL_CLIENT_ID": "5c1d7e2a-33b4-4e0a-8f6d-9a1b2c3d4e5f",
    "MICROSOFT_DEFENDER_INTEL_CLIENT_SECRET": "staticfire-fake-secret",
}
CALLS = ["/microsoft-defender/api/indicators"]

SPECS = [
    ConnectorSpec(
        recipe="microsoft-defender-intel",
        connector="stream/microsoft-defender-intel",
        env=lambda fake: ENV,
        stream_filters=FILTERS,
        stream=_objects,
        calls=CALLS,
        description="a new indicator and a scored observable become Defender custom "
        "indicators (type, value, action, expiration), linked back through an external "
        "reference (own stream limited to the test's objects)",
    ),
    ConnectorSpec(
        recipe="microsoft-defender-intel-unscored",
        connector="stream/microsoft-defender-intel",
        env=lambda fake: ENV,
        calls=CALLS,
        description="an indicator and an IPv4 observable without a score: the observable "
        "makes get_action/get_severity compare None with an int (connector defect)",
    ),
]
