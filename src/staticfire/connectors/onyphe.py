import uuid

from staticfire.connector_vendors import ConnectorSpec


def _onyphe_indicator(cti) -> str:
    """An indicator whose pattern is an ONYPHE OQL query (the connector creates the type)."""
    name = f"staticfire_{uuid.uuid4().hex[:8]}"
    query = "category:ctiscan ip.organization:staticfire"
    return cti.create_indicator(name, query, "IPv4-Addr", pattern_type="onyphe")["id"]


SPECS = [
    ConnectorSpec(
        recipe="onyphe",
        connector="internal-enrichment/onyphe",
        env=lambda fake: {"ONYPHE_API_KEY": "staticfire-fake-key", "ONYPHE_CREATE_NOTE": "true"},
        enrich=("IPv4-Addr", "203.0.113.45"),
        expected_types={
            "identity",
            "autonomous-system",
            "domain-name",
            "hostname",
            "x509-certificate",
            "text",
            "note",
            "ipv4-addr",
            "relationship:belongs-to",
            "relationship:related-to",
            "relationship:resolves-to",
        },
        calls=["/onyphe/api/v2/search/"],
        description="ctiscan results for an address become ASN, domains, hostnames, certificates",
    ),
    ConnectorSpec(
        recipe="onyphe-riskscan",
        connector="internal-enrichment/onyphe",
        env=lambda fake: {
            "ONYPHE_API_KEY": "staticfire-fake-key",
            "ONYPHE_CATEGORY": "riskscan",
        },
        enrich=("IPv4-Addr", "203.0.113.46"),
        expected_types={
            "vulnerability",
            "autonomous-system",
            "domain-name",
            "hostname",
            "x509-certificate",
            "relationship:related-to",
        },
        calls=["/onyphe/api/v2/search/"],
        description="riskscan results for an address become vulnerabilities and certificates",
    ),
    ConnectorSpec(
        recipe="onyphe-indicator",
        connector="internal-enrichment/onyphe",
        env=lambda fake: {"ONYPHE_API_KEY": "staticfire-fake-key"},
        enrich=_onyphe_indicator,
        expected_types={"note", "ipv4-addr", "domain-name", "autonomous-system"},
        calls=["/onyphe/api/v2/search/"],
        description="an indicator holding an OQL query gets a summary note and the results",
    ),
]
