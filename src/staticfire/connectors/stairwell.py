import hashlib
import uuid

from staticfire.connector_vendors import ConnectorSpec

# Both specs share the connector's id: one name, as the platform knows it
_ENV = {"STAIRWELL_API_TOKEN": "staticfire-fake-key", "STAIRWELL_SIGHTINGS_LIMIT": "5"}


def _new_file(cti) -> str:
    """A file observable on a hash Stairwell has never been asked about before."""
    return cti.create_file_observable(hashlib.sha256(uuid.uuid4().bytes).hexdigest())["id"]


def _new_domain(cti) -> str:
    return cti.create_observable("Domain-Name", f"sf-{uuid.uuid4().hex[:10]}.example.com")["id"]


def _new_ip(cti) -> str:
    octets = uuid.uuid4().bytes
    # public-looking: the connector skips nothing, but OpenCTI keeps what earlier runs made
    address = f"93.{octets[0]}.{octets[1]}.{octets[2] % 253 + 1}"
    return cti.create_observable("IPv4-Addr", address)["id"]


def _new_asn(cti) -> str:
    number = 64000 + uuid.uuid4().int % 1000
    return cti.graphql(
        """mutation ($number: Int!) {
             stixCyberObservableAdd(type: "Autonomous-System",
               AutonomousSystem: { number: $number }) { id } }""",
        {"number": number},
    )["stixCyberObservableAdd"]["id"]


SPECS = [
    ConnectorSpec(
        recipe="stairwell",
        connector="internal-enrichment/stairwell",
        env=lambda fake: _ENV,
        enrich=_new_file,
        expected_types={
            "file",
            "note",
            "ipv4-addr",
            "domain-name",
            "url",
            "sighting",
            "identity",
            "relationship:derived-from",
            "relationship:related-to",
        },
        calls=[
            "/stairwell/v1/objects/",
            "/stairwell/v202112/variants/",
        ],
        description="a file gets its MalEval score and labels, summary notes, lineage and variant "
        "files, network observables and per-asset sightings",
    ),
    ConnectorSpec(
        recipe="stairwell-domain",
        connector="internal-enrichment/stairwell",
        env=lambda fake: _ENV,
        enrich=_new_domain,
        expected_types={
            "note",
            "ipv4-addr",
            "ipv6-addr",
            "domain-name",
            "relationship:resolves-to",
        },
        calls=["/stairwell/v2/hostnames/"],
        description="a domain gets its DNS history note and the addresses and names it resolves to",
    ),
    ConnectorSpec(
        recipe="stairwell-ip",
        connector="internal-enrichment/stairwell",
        env=lambda fake: _ENV,
        enrich=_new_ip,
        expected_types={"note", "autonomous-system", "relationship:belongs-to"},
        calls=["/stairwell/v2/ips/"],
        description="an address gets its cloud labels, WHOIS and reverse DNS note and its AS",
    ),
    ConnectorSpec(
        recipe="stairwell-asn",
        connector="internal-enrichment/stairwell",
        env=lambda fake: _ENV,
        enrich=_new_asn,
        expected_types={"note", "autonomous-system"},
        calls=["/stairwell/v2/asns/"],
        description="an autonomous system gets its holder name and WHOIS note",
    ),
]
