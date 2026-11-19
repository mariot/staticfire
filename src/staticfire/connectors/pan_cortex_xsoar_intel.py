import uuid

from staticfire.connector_vendors import ConnectorSpec

DOMAIN = "xsoar.staticfire.example.com"
# The shared test stream carries the indicators of every test: the connector logs an error for
# those it cannot map. The test follows its own stream, limited to the indicators it creates.
FILTERS = {
    "mode": "and",
    "filters": [
        {"key": ["entity_type"], "values": ["Indicator"], "operator": "eq", "mode": "or"},
        {"key": ["pattern"], "values": [DOMAIN], "operator": "contains", "mode": "or"},
    ],
    "filterGroups": [],
}


def _domain_indicator(cti) -> list[str]:
    domain = f"sf-{uuid.uuid4().hex[:8]}.{DOMAIN}"
    cti.create_indicator(f"staticfire {domain}", f"[domain-name:value = '{domain}']", "Domain-Name")
    return [domain]


SPEC = ConnectorSpec(
    recipe="pan-cortex-xsoar-intel",
    connector="stream/pan-cortex-xsoar-intel",
    env=lambda fake: {
        "XSOAR_URL": "https://xsoar-staticfire.xdr.us.paloaltonetworks.com",
        "XSOAR_KEY_ID": "1",
        "XSOAR_KEY": "staticfire-fake-key",
    },
    stream_filters=FILTERS,
    stream=_domain_indicator,
    calls=["/pan-cortex-xsoar-intel/xsoar/public/v1/indicator/create"],
    description="a new indicator is translated through stix-shifter and created in Cortex "
    "XSOAR with its score, tags and TLP (own stream limited to the test's indicators)",
)
