from staticfire.connector_vendors import ConnectorSpec

SPEC = ConnectorSpec(
    recipe="dnstwist",
    connector="internal-enrichment/dnstwist",
    env=lambda fake: {"DNS_TWIST_FETCH_REGISTERED": "false", "DNS_TWIST_THREADS": "10"},
    enrich=("Domain-Name", "a.io"),
    expected_types={"domain-name", "relationship:related-to"},
    timeout=900,
    description=(
        "the permutations of a domain (computed locally) become related domain-names; "
        "dnstwist's own DNS/whois lookups are not proxied, so hosting objects need a network"
    ),
)
