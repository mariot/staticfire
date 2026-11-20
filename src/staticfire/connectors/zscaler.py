import uuid

from staticfire.connector_vendors import ConnectorSpec

DOMAIN = "zscaler.staticfire.example.com"
# the test follows its own stream, limited to the domain indicators it creates
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
    recipe="zscaler",
    connector="stream/zscaler",
    env=lambda fake: {
        "ZSCALER_CLIENT_ID": "staticfire-client",
        "ZSCALER_CLIENT_SECRET": "staticfire-secret",
        "ZSCALER_VANITY_DOMAIN": "staticfire",
    },
    stream_filters=FILTERS,
    stream=_domain_indicator,
    calls=[
        "/zscaler/oauth2/v1/token",
        "/zscaler/zia/api/v1/urlLookup",
        "/zscaler/zia/api/v1/urlCategories/",
    ],
    description="a domain indicator is looked up, then added to the blacklist URL category "
    "(own stream limited to the test's indicators)",
)
