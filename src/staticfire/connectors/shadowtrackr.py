import random

from staticfire.connector_vendors import ConnectorSpec


def _new_address(cti) -> str:
    """A public IPv4 address no earlier run touched: the connector refuses an address it
    already described."""
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
    recipe="shadowtrackr",
    connector="internal-enrichment/shadowtrackr",
    env=lambda fake: {
        "SHADOWTRACKR_API_KEY": "staticfire-fake-key",
        "SHADOWTRACKR_REPLACE_WITH_LOWER_SCORE": "true",
    },
    enrich=_new_address,
    expected_types={"ipv4-addr", "identity"},
    calls=["/shadowtrackr/api/v3/ip_info"],
    description="a CDN address gets the cdn label, a description and a lower score",
)
