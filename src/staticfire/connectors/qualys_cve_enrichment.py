import uuid

from staticfire.connector_vendors import ConnectorSpec


def _vulnerability(cti) -> str:
    return cti.graphql(
        """mutation ($input: VulnerabilityAddInput!) { vulnerabilityAdd(input: $input) { id } }""",
        {"input": {"name": f"CVE-2024-{uuid.uuid4().int % 90000 + 10000}"}},
    )["vulnerabilityAdd"]["id"]


SPEC = ConnectorSpec(
    recipe="qualys-cve-enrichment",
    connector="internal-enrichment/qualys-cve-enrichment",
    env=lambda fake: {
        "QUALYS_CVE_ENRICHMENT_USERNAME": "staticfire",
        "QUALYS_CVE_ENRICHMENT_PASSWORD": "staticfire-fake-secret",
    },
    enrich=_vulnerability,
    expected_types={"vulnerability", "software", "identity", "note", "relationship:has"},
    calls=[
        "/qualys/api/3.0/fo/knowledge_base/vuln/",
        "/qualys/api/3.0/fo/asset/host/vm/detection/",
    ],
    description="a CVE gets its Qualys KnowledgeBase data (CVSS, QDS, notes, software) and "
    "the hosts it was detected on (legacy XML APIs)",
)
