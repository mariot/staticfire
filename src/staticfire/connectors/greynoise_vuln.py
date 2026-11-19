from staticfire.connector_vendors import ConnectorSpec


def _vulnerability(cti) -> str:
    return cti.graphql(
        """mutation ($input: VulnerabilityAddInput!) { vulnerabilityAdd(input: $input) { id } }""",
        {"input": {"name": "CVE-2021-44228"}},
    )["vulnerabilityAdd"]["id"]


SPEC = ConnectorSpec(
    recipe="greynoise-vuln",
    connector="internal-enrichment/greynoise-vuln",
    env=lambda fake: {"GREYNOISE_VULN_KEY": "staticfire-fake-key"},
    enrich=_vulnerability,
    expected_types={"vulnerability", "note", "software", "identity", "relationship:has"},
    calls=["/greynoise/v1/cve/"],
    description="a CVE gets its GreyNoise exploitation note, labels, CVSS/EPSS and software",
)
