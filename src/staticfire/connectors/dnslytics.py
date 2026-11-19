import uuid

from staticfire.connector_vendors import ConnectorSpec


def _dnslytics_query(cti) -> str:
    query = f"(name:*{uuid.uuid4().hex[:6]}*) AND (name:*staticfire*)"
    return cti.create_indicator(query, query, "Domain-Name", pattern_type="dnslytics")["id"]


SPEC = ConnectorSpec(
    recipe="dnslytics",
    connector="internal-enrichment/dnslytics",
    env=lambda fake: {"DNSLYTICS_API_KEY": "staticfire-fake-key"},
    enrich=_dnslytics_query,
    expected_types={"indicator", "domain-name", "relationship:based-on"},
    calls=["/dnslytics/v2/dataset/domains"],
    description=(
        "a dnslytics-type indicator is run as a domain search: each hit becomes a domain-name "
        "the indicator is based on (DNS resolution is real: hosting objects need a network)"
    ),
)
