import uuid

from staticfire.connector_vendors import ConnectorSpec


def _ip_indicator(cti) -> list[str]:
    """An indicator on a new IPv4 address: FortiEDR IP sets only take addresses."""
    token = uuid.uuid4().hex
    ip = f"198.51.{int(token[:2], 16) % 256}.{int(token[2:4], 16) % 254 + 1}"
    cti.create_indicator(f"staticfire {ip}", f"[ipv4-addr:value = '{ip}']", "IPv4-Addr")
    return [ip]


SPEC = ConnectorSpec(
    recipe="fortiedr",
    connector="stream/fortiedr",
    env=lambda fake: {
        "FORTIEDR_API_BASE_URL": "https://staticfire.console.ensilo.com",
        "FORTIEDR_USERNAME": "staticfire",
        "FORTIEDR_PASSWORD": "staticfire-fake-secret",
    },
    stream=_ip_indicator,
    calls=["/fortiedr/management-rest/ip-sets/"],
    description="an indicator on an IPv4 address is added to the managed FortiEDR IP set",
)
