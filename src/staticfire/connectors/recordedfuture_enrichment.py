from staticfire.connector_vendors import ConnectorSpec

ENV = {"RECORDED_FUTURE_TOKEN": "staticfire-fake-key"}


def _vulnerability(cti) -> str:
    return cti.graphql(
        """mutation ($input: VulnerabilityAddInput!) { vulnerabilityAdd(input: $input) { id } }""",
        {"input": {"name": "CVE-2021-44228"}},
    )["vulnerabilityAdd"]["id"]


SPECS = [
    ConnectorSpec(
        recipe="recordedfuture-enrichment",
        connector="internal-enrichment/recordedfuture-enrichment",
        env=lambda fake: ENV,
        enrich=("IPv4-Addr", "185.220.101.45"),
        expected_types={
            "indicator",
            "note",
            "malware",
            "threat-actor",
            "vulnerability",
            "attack-pattern",
            "domain-name",
            "url",
            "file",
            "relationship:based-on",
        },
        calls=["/recorded-future/v2/ip/", "/recorded-future/links/search"],
        description="an IP gets its risk notes, indicator and the linked malware, actors, "
        "techniques and indicators",
    ),
    ConnectorSpec(
        recipe="recordedfuture-enrichment-vulnerability",
        connector="internal-enrichment/recordedfuture-enrichment",
        env=lambda fake: ENV,
        enrich=_vulnerability,
        expected_types={"vulnerability", "note", "software", "relationship:has"},
        calls=["/recorded-future/v2/vulnerability/"],
        description="a CVE gets its CVSS v2/v3/v4, aliases, CPE software, references and "
        "risk notes",
    ),
]
