import uuid

from staticfire.connector_vendors import ConnectorSpec


def _report(cti) -> str:
    """An ESET report holding the Text observable with its ETI portal download link."""
    eset = cti.graphql(
        """mutation ($input: OrganizationAddInput!) { organizationAdd(input: $input) { id } }""",
        {"input": {"name": "ESET"}},
    )["organizationAdd"]
    link = cti.graphql(
        """mutation ($value: String!) {
             stixCyberObservableAdd(type: "Text", Text: { value: $value }) { id } }""",
        {"value": f"https://www.eset.com/reports/apt/{uuid.uuid4()}/download"},
    )["stixCyberObservableAdd"]
    return cti.graphql(
        """mutation ($input: ReportAddInput!) { reportAdd(input: $input) { id } }""",
        {
            "input": {
                "name": f"ESET APT Activity Report {uuid.uuid4().hex[:6]}",
                "published": "2026-01-01T00:00:00.000Z",
                "report_types": ["APT Report"],
                "createdBy": eset["id"],
                "objects": [link["id"]],
            }
        },
    )["reportAdd"]["id"]


SPEC = ConnectorSpec(
    recipe="eset-enrichment",
    connector="internal-enrichment/eset-enrichment",
    env=lambda fake: {
        "ESET_API_KEY": "staticfire-fake-key",
        "ESET_API_SECRET": "staticfire-fake-secret",
    },
    enrich=_report,
    expected_types={"report"},
    calls=["/eset/api/v2/apt-reports/"],
    description="an ESET report with its portal link gets the APT report PDF attached "
    "(uploaded as a report file, not in the bundle)",
)
