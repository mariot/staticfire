import uuid

from staticfire.connector_vendors import ConnectorSpec

DOMAIN = "xdr.staticfire.example.com"
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
    recipe="pan-cortex-xdr-intel",
    connector="stream/pan-cortex-xdr-intel",
    env=lambda fake: {
        "PAN_CORTEX_XDR_INTEL_API_BASE_URL": "https://api-staticfire.xdr.us.paloaltonetworks.com",
        "PAN_CORTEX_XDR_INTEL_API_KEY_ID": "1",
        "PAN_CORTEX_XDR_INTEL_API_KEY": "staticfire-fake-key",
    },
    stream_filters=FILTERS,
    stream=_domain_indicator,
    calls=["/pan-cortex-xdr-intel/public_api/v1/indicators/insert"],
    description="a new indicator is looked up in Cortex XDR then inserted as an IOC, with "
    "severity and reputation from its score (own stream limited to the test's indicators)",
)
