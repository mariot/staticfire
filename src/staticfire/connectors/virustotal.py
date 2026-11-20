import hashlib
import uuid

from staticfire.connector_vendors import ConnectorSpec

GTI = {
    "VIRUSTOTAL_GTI_ENRICHMENT_ENABLED": "true",
    "VIRUSTOTAL_GTI_INCLUDE_MALWARE_FAMILIES": "true",
    "VIRUSTOTAL_GTI_INCLUDE_THREAT_ACTORS": "true",
    "VIRUSTOTAL_GTI_INCLUDE_CAMPAIGNS": "true",
    "VIRUSTOTAL_GTI_INCLUDE_REPORTS": "true",
}


def _file(cti) -> str:
    """A new file hash VirusTotal knows (hashes starting with 00 are unseen to the fake)."""
    while (digest := hashlib.sha256(uuid.uuid4().bytes).hexdigest()).startswith("00"):
        pass
    return cti.create_file_observable(digest)["id"]


def _unseen_artifact(cti) -> str:
    """An artifact VirusTotal has no record of: it is uploaded, analysed and read again."""
    while True:
        content = b"MZ" + uuid.uuid4().bytes * 8
        if hashlib.sha256(content).hexdigest().startswith("00"):
            return cti.create_artifact(content, "staticfire-sample.exe", "application/x-dosexec")


def _unseen_url(cti) -> str:
    return cti.create_observable(
        "Url", f"https://unseen-{uuid.uuid4().hex[:10]}.example.com/a.exe"
    )["id"]


def _spec(recipe: str, enrich, expected: set[str], description: str, **env: str):
    return ConnectorSpec(
        recipe=recipe,
        connector="internal-enrichment/virustotal",
        env=lambda fake: {"VIRUSTOTAL_TOKEN": "staticfire-fake-key", **GTI, **env},
        enrich=enrich,
        expected_types=expected,
        calls=["/virustotal/api/v3/"],
        description=description,
    )


SPECS = [
    _spec(
        "virustotal",
        _file,
        {"indicator", "note", "malware", "intrusion-set", "campaign", "report"},
        "a file hash gets its score, labels, a file indicator, the report note, the "
        "crowdsourced YARA rules and the GTI families, actors, campaigns and reports",
    ),
    _spec(
        "virustotal-artifact",
        _unseen_artifact,
        {"indicator", "note"},
        "an artifact VirusTotal never saw is uploaded and its analysis awaited before "
        "it is enriched",
    ),
    _spec(
        "virustotal-ip",
        ("IPv4-Addr", "185.220.101.34"),
        {"indicator", "note", "autonomous-system", "location", "domain-name", "malware"},
        "an address gets ASN and country, a note, an indicator and the domains resolving "
        "to it, page by page",
        VIRUSTOTAL_IP_ADD_RELATIONSHIPS="true",
        VIRUSTOTAL_IP_ADD_RESOLUTIONS="true",
        VIRUSTOTAL_API_REQUESTS_PER_MINUTE="0",
    ),
    _spec(
        "virustotal-domain",
        ("Domain-Name", "staticfire-dropper.example.org"),
        {"indicator", "note", "malware"},
        "a domain gets its score, labels, notes and indicator",
        VIRUSTOTAL_DOMAIN_ADD_RELATIONSHIPS="true",
    ),
    _spec(
        "virustotal-url",
        _unseen_url,
        {"indicator", "note"},
        "a URL VirusTotal never saw is submitted and analysed, then enriched (its last "
        "serving address goes in the note)",
        VIRUSTOTAL_INCLUDE_ATTRIBUTES_IN_NOTE="true",
    ),
]
