import uuid

from staticfire.connector_vendors import ConnectorSpec

CALLS = ["/rstcloud/v1/ioc"]


def _indicator(cti) -> str:
    # a fresh public address: an indicator already enriched would be updated in place
    address = f"203.0.{uuid.uuid4().int % 250 + 1}.{uuid.uuid4().int % 250 + 1}"
    return cti.create_indicator(address, f"[ipv4-addr:value = '{address}']", "IPv4-Addr")["id"]


ENV = {"RST_IOC_LOOKUP_API_KEY": "staticfire-fake-key"}

SPECS = [
    ConnectorSpec(
        recipe="rst-ioc-lookup",
        connector="internal-enrichment/rst-ioc-lookup",
        env=lambda fake: ENV,
        enrich=("IPv4-Addr", "203.0.113.200"),
        expected_types={"ipv4-addr"},
        calls=CALLS,
        description="an address is looked up (score, threats, geo, ASN) and updated with its "
        "labels, score, description and references",
    ),
    ConnectorSpec(
        recipe="rst-ioc-lookup-indicator",
        connector="internal-enrichment/rst-ioc-lookup",
        env=lambda fake: ENV,
        enrich=_indicator,
        expected_types={"indicator"},
        calls=CALLS,
        description="an indicator is looked up by its name and gets its score, confidence, "
        "detection flag, validity period, labels and references",
    ),
]
