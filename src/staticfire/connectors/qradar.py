import uuid

from staticfire.connector_vendors import ConnectorSpec

DOMAIN = "qradar.staticfire.test"
# Its own stream, limited to the indicators the test creates: the shared one carries every
# object of the platform
FILTERS = {
    "mode": "and",
    "filters": [
        {"key": ["entity_type"], "values": ["Indicator"], "operator": "eq", "mode": "or"},
        {"key": ["pattern"], "values": [DOMAIN], "operator": "contains", "mode": "or"},
    ],
    "filterGroups": [],
}


def _indicator(cti) -> list[str]:
    """One indicator whose pattern holds a domain, an address, a URL and an MD5 hash: each goes
    to its own reference set."""
    token = uuid.uuid4().hex
    domain = f"sf-{token[:8]}.{DOMAIN}"
    ip = f"198.51.{int(token[:2], 16) % 256}.{int(token[2:4], 16) % 254 + 1}"
    url = f"https://{domain}/payload-{token[8:12]}"
    md5 = token
    pattern = (
        f"[domain-name:value = '{domain}'] OR [ipv4-addr:value = '{ip}'] OR "
        f"[url:value = '{url}'] OR [file:hashes.MD5 = '{md5}']"
    )
    cti.create_indicator(f"staticfire qradar {domain}", pattern, "Domain-Name")
    return [domain, ip, url, md5]


SPEC = ConnectorSpec(
    recipe="qradar-cti",
    connector="stream/qradar",
    env=lambda fake: {
        "QRADAR_URL": f"https://{DOMAIN}",
        "QRADAR_TOKEN": "staticfire-fake-key",
        "QRADAR_IGNORE_TYPES": "label,marking-definition,identity,organization",
    },
    stream_filters=FILTERS,
    stream=_indicator,
    calls=[
        "/qradar-reference-data/api/reference_data_collections/sets",
        "/qradar-reference-data/api/reference_data_collections/set_entries",
    ],
    description="an indicator's domain, address, URL and MD5 are added to QRadar reference sets "
    "(own stream limited to the test's indicators)",
)
