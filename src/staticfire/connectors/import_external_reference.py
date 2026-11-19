import uuid

from staticfire.connector_vendors import ConnectorSpec

# The connector's headless browser ignores the proxy variables: the pages are on ofapi itself
OFAPI = "http://127.0.0.1:8000/import-external-reference"


def _external_reference(path: str):
    def create(cti) -> str:
        token = uuid.uuid4().hex[:8]
        return cti.graphql(
            """mutation ($input: ExternalReferenceAddInput!) {
                 externalReferenceAdd(input: $input) { id } }""",
            {
                "input": {
                    "source_name": "staticfire",
                    "url": f"{OFAPI}/{path.format(token=token)}",
                    "description": "staticfire import-external-reference",
                }
            },
        )["externalReferenceAdd"]["id"]

    return create


SPECS = [
    ConnectorSpec(
        recipe="import-external-reference",
        connector="internal-enrichment/import-external-reference",
        enrich=_external_reference("blog/threat-report-{token}"),
        calls=["/import-external-reference/blog/"],
        description="a web page is rendered by the headless browser and attached to the "
        "external reference as a PDF and a Markdown file (uploads, not in the bundles)",
    ),
    ConnectorSpec(
        recipe="import-external-reference-pdf",
        connector="internal-enrichment/import-external-reference",
        enrich=_external_reference("reports/threat-report-{token}.pdf"),
        calls=["/import-external-reference/reports/"],
        description="a PDF report is downloaded and attached to the external reference as a "
        "PDF and a Markdown conversion (uploads, not in the bundles)",
    ),
]
