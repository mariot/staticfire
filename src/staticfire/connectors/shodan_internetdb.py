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


SPEC = ConnectorSpec(
    recipe="shodan-internetdb",
    connector="internal-enrichment/shodan-internetdb",
    enrich=_new_address,
    expected_types={"ipv4-addr", "domain-name", "vulnerability", "note", "identity"},
    calls=["/shodan-service/"],
    description="an address gets its InternetDB hostnames, vulnerabilities, tags and a note",
)
