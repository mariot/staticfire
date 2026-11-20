import uuid

from staticfire.connector_vendors import ConnectorSpec


def _env(fake):
    return {
        "PURE_SIGNAL_SCOUT_API_TOKEN": "staticfire-fake-key",
        "PURE_SIGNAL_SCOUT_API_URL": "https://taxii.cymru.com/api/scout",
    }


def _domain(cti) -> str:
    return cti.create_observable("Domain-Name", f"sf-{uuid.uuid4().hex[:8]}.example.com")["id"]


_TYPES = {"ipv4-addr", "autonomous-system", "location", "identity", "indicator"}

SPECS = [
    ConnectorSpec(
        recipe="team-cymru-scout",
        connector="internal-enrichment/team-cymru-scout",
        env=_env,
        enrich=("IPv4-Addr", "185.220.101.45"),
        expected_types=_TYPES | {"domain-name", "relationship:based-on", "relationship:belongs-to"},
        calls=["/team-cymru/api/scout/ip/foundation"],
        description="an address gets its network, owner, country, peers and indicator "
        "from the Scout foundation bundle",
    ),
    ConnectorSpec(
        recipe="team-cymru-scout-domain",
        connector="internal-enrichment/team-cymru-scout",
        env=_env,
        enrich=_domain,
        expected_types=_TYPES | {"domain-name", "relationship:based-on"},
        calls=["/team-cymru/api/scout/search"],
        description="a domain name is searched in Scout and its bundle ingested",
    ),
]
