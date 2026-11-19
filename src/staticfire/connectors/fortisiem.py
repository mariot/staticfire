import uuid

from staticfire.connector_vendors import ConnectorSpec


def _indicators(cti) -> list[str]:
    """Indicators on a new IPv4 address and a new domain: watch lists take any value."""
    token = uuid.uuid4().hex[:8]
    domain = f"sf-{token}.example.com"
    ip = f"198.51.{int(token[:2], 16) % 256}.{int(token[2:4], 16) % 254 + 1}"
    cti.create_indicator(f"staticfire {ip}", f"[ipv4-addr:value = '{ip}']", "IPv4-Addr")
    cti.create_indicator(f"staticfire {domain}", f"[domain-name:value = '{domain}']", "Domain-Name")
    return [ip, domain]


SPEC = ConnectorSpec(
    recipe="fortisiem",
    connector="stream/fortisiem",
    env=lambda fake: {
        "FORTISIEM_API_BASE_URL": "https://fortisiem.staticfire.test",
        "FORTISIEM_USERNAME": "staticfire",
        "FORTISIEM_PASSWORD": "staticfire-fake-secret",
        "FORTISIEM_WATCHLIST_ID": "4242",
    },
    stream=_indicators,
    calls=["/fortisiem/phoenix/rest/watchlist/addTo"],
    description="indicators on an IPv4 address and a domain are added to the FortiSIEM watch list",
)
