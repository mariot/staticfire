import uuid

from staticfire.connector_vendors import ConnectorSpec


def _ip_indicator(cti) -> list[str]:
    """An indicator on a new IPv4 address: the only kind the connector forwards."""
    token = uuid.uuid4().hex
    ip = f"198.51.{int(token[:2], 16) % 256}.{int(token[2:4], 16) % 254 + 1}"
    cti.create_indicator(f"staticfire {ip}", f"[ipv4-addr:value = '{ip}']", "IPv4-Addr")
    return [ip]


SPEC = ConnectorSpec(
    recipe="akamai",
    connector="stream/akamai",
    env=lambda fake: {
        "AKAMAI_BASE_URL": "https://staticfire.akamaiapis.net",
        "AKAMAI_CLIENT_TOKEN": "akab-client-token",
        "AKAMAI_CLIENT_SECRET": "staticfire-fake-secret",
        "AKAMAI_ACCESS_TOKEN": "akab-access-token",
        "AKAMAI_CLIENT_LIST_ID": "12345_STATICFIRE",
    },
    stream=_ip_indicator,
    calls=["/akamai/client-list/v1/lists/12345_STATICFIRE/items"],
    description="an indicator on an IPv4 address is appended to the Akamai client list",
)
