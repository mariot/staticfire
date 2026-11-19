import uuid

from staticfire.connector_vendors import ConnectorSpec

FEED = "https://api.datadoghq.com/api/v2/security/threat-intel-feed"


def _env(fake) -> dict[str, str]:
    return {
        "DATADOG_INTEL_INTEGRATION_API_URL": FEED,
        "DATADOG_INTEL_DD_API_KEY": "staticfire-fake-key",
        "DATADOG_INTEL_DD_APPLICATION_KEY": "staticfire-fake-app-key",
        "DATADOG_INTEL_INDICATOR_TYPE": "ip_address,domain,sha256",
    }


def _stream(cti) -> list[str]:
    """Indicators on an IPv4, a domain and a SHA-256, one per type the connector forwards."""
    token = uuid.uuid4().hex[:8]
    domain = f"sf-{token}.example.com"
    ip = f"198.51.{int(token[:2], 16) % 256}.{int(token[2:4], 16) % 254 + 1}"
    sha256 = uuid.uuid4().hex + uuid.uuid4().hex
    cti.create_indicator(f"staticfire {ip}", f"[ipv4-addr:value = '{ip}']", "IPv4-Addr")
    cti.create_indicator(f"staticfire {domain}", f"[domain-name:value = '{domain}']", "Domain-Name")
    cti.create_indicator(
        f"staticfire {sha256[:8]}", f"[file:hashes.'SHA-256' = '{sha256}']", "StixFile"
    )
    return [ip, domain, sha256]


SPEC = ConnectorSpec(
    recipe="datadog-intel",
    connector="stream/datadog-intel",
    env=_env,
    stream=_stream,
    calls=["/datadog/api/v2/security/threat-intel-feed/received"],
    timeout=180,
    description="new indicators (IPv4, domain, SHA-256) are batched and pushed gzipped to the "
    "Datadog threat intel feed",
)
