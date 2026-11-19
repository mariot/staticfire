import hashlib

from staticfire.connector_vendors import ConnectorSpec

SHA256 = hashlib.sha256(b"staticfire polyswarm enrichment 2").hexdigest()

SPEC = ConnectorSpec(
    recipe="polyswarm-enrichment",
    connector="internal-enrichment/polyswarm-enrichment",
    env=lambda fake: {"POLYSWARM_API_KEY": "staticfire-fake-key"},
    enrich=("StixFile", SHA256),
    expected_types={
        "indicator",
        "malware",
        "note",
        "ipv4-addr",
        "domain-name",
        "url",
        "relationship:indicates",
        "relationship:communicates-with",
        "relationship:related-to",
    },
    calls=["/polyswarm/v3/search/hash/", "/polyswarm/v3/tags/link", "/polyswarm/v3/ioc/"],
    description="a file hash gets its PolyScore, family, indicator and sandbox network IOCs",
)
