import uuid

from staticfire.connector_vendors import ConnectorSpec


def _vulnerability(cti) -> str:
    return cti.graphql(
        """mutation ($input: VulnerabilityAddInput!) { vulnerabilityAdd(input: $input) { id } }""",
        {"input": {"name": f"CVE-2024-{uuid.uuid4().int % 90000 + 10000}"}},
    )["vulnerabilityAdd"]["id"]


SPEC = ConnectorSpec(
    recipe="first-epss",
    connector="internal-enrichment/first-epss",
    enrich=_vulnerability,
    expected_types={"vulnerability", "identity"},
    calls=["/first-epss/data/v1/epss"],
    description="a CVE gets its EPSS score and percentile from the FIRST API",
)
