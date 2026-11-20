import uuid

from staticfire.connector_vendors import ConnectorSpec

SPEC = ConnectorSpec(
    recipe="urlscan-enrichment",
    connector="internal-enrichment/urlscan-enrichment",
    env=lambda fake: {"URLSCAN_ENRICHMENT_API_KEY": "staticfire-fake-key"},
    enrich=lambda cti: cti.create_observable(
        "Url", f"https://secure-{uuid.uuid4().hex[:8]}.example-bank.com/signin"
    )["id"],
    expected_types={
        "hostname",
        "ipv4-addr",
        "autonomous-system",
        "indicator",
        "relationship:related-to",
        "relationship:based-on",
        "relationship:belongs-to",
        "relationship:resolves-to",
    },
    calls=["/urlscan/api/v1/scan/", "/urlscan/api/v1/result/", "/urlscan/screenshots/"],
    timeout=420,
    description="a URL is submitted to a urlscan scan (result unfinished at first, then "
    "complete); its IPs, ASNs, hostnames, labels, screenshot and indicator enrich it",
)
