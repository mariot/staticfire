from staticfire.connector_vendors import ConnectorSpec

SPEC = ConnectorSpec(
    recipe="greynoise",
    connector="internal-enrichment/greynoise",
    env=lambda fake: {"GREYNOISE_KEY": "staticfire-fake-key"},
    enrich=("IPv4-Addr", "185.220.101.45"),
    expected_types={
        "indicator",
        "location",
        "malware",
        "threat-actor",
        "tool",
        "vulnerability",
        "autonomous-system",
        "domain-name",
        "sighting",
        "relationship:based-on",
    },
    calls=["/greynoise/v3/ip/"],
    description="a malicious scanner IP gets its indicator, labels, ASN, rdns, location, CVEs, "
    "VPN tool, worm malware, actor and sightings",
)
