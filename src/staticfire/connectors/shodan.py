import random

from staticfire.connector_vendors import ConnectorSpec


def _new_address(cti) -> str:
    """A public IPv4 address as a user adds it."""
    value = ".".join(
        str(part)
        for part in (
            random.choice([45, 91, 103, 185, 194]),
            random.randint(1, 254),
            random.randint(1, 254),
            random.randint(1, 254),
        )
    )
    return cti.graphql(
        """mutation ($value: String!) {
             stixCyberObservableAdd(type: "IPv4-Addr", IPv4Addr: { value: $value }) { id } }""",
        {"value": value},
    )["stixCyberObservableAdd"]["id"]


def _new_search(cti) -> str:
    """An indicator holding a Shodan query, which the connector runs."""
    name = f"staticfire shodan search {random.randint(1, 10**9)}"
    return cti.graphql(
        """mutation ($name: String!, $pattern: String!) {
             indicatorAdd(input: { name: $name, pattern: $pattern, pattern_type: "shodan",
                                   x_opencti_main_observable_type: "IPv4-Addr",
                                   valid_from: "2025-01-01T00:00:00.000Z" }) { id } }""",
        {"name": name, "pattern": f"port:443 org:staticfire{random.randint(1, 10**9)}"},
    )["indicatorAdd"]["id"]


ENV = {"SHODAN_TOKEN": "staticfire-fake-key"}

SPECS = [
    ConnectorSpec(
        recipe="shodan",
        connector="internal-enrichment/shodan",
        env=lambda fake: dict(ENV),
        enrich=_new_address,
        expected_types={
            "ipv4-addr",
            "domain-name",
            "hostname",
            "autonomous-system",
            "x509-certificate",
            "location",
            "vulnerability",
            "note",
            "identity",
            "relationship:related-to",
            "relationship:located-at",
            "relationship:belongs-to",
        },
        calls=["/shodan-service/shodan/host/"],
        description="an address gets its host record: organization, domains, AS, certificate, "
        "locations, vulnerabilities and a services note",
    ),
    ConnectorSpec(
        recipe="shodan-search",
        connector="internal-enrichment/shodan",
        env=lambda fake: dict(ENV),
        enrich=_new_search,
        expected_types={"ipv4-addr", "note", "vulnerability", "relationship:related-to"},
        calls=[
            "/shodan-service/shodan/host/count",
            "/shodan-service/shodan/host/search",
            "/shodan-service/shodan/host/",
        ],
        description="an indicator holding a Shodan query gets a facets note and its matching hosts",
    ),
]
