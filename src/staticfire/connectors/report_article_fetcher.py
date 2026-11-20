import uuid

from staticfire.connector_vendors import ConnectorSpec


def _report(cti) -> str:
    """A report as the RSS ingestion writes it: its name, and one external reference whose
    source is the name and whose description ends with the retrieval date."""
    token = uuid.uuid4().hex[:8]
    name = f"Staticfire {token} ransomware campaign targets hospitals"
    reference = cti.graphql(
        """mutation ($input: ExternalReferenceAddInput!) {
             externalReferenceAdd(input: $input) { id } }""",
        {
            "input": {
                "source_name": name,
                "url": f"https://www.example.net/news/{name.lower().replace(' ', '-')}",
                "description": f"Staticfire feed {name}. Retrieved 2026-11-19T08:00:00.000Z.",
            }
        },
    )["externalReferenceAdd"]
    return cti.graphql(
        """mutation ($input: ReportAddInput!) { reportAdd(input: $input) { id } }""",
        {
            "input": {
                "name": name,
                "published": "2026-11-19T08:00:00.000Z",
                "report_types": ["threat-report"],
                "externalReferences": [reference["id"]],
            }
        },
    )["reportAdd"]["id"]


SPEC = ConnectorSpec(
    recipe="report-article-fetcher",
    connector="internal-enrichment/report-article-fetcher",
    # the per-report summary is written at error level by default: info keeps the log judgeable
    env=lambda fake: {
        "REPORT_ARTICLE_FETCHER_SUMMARY_LOG_LEVEL": "info",
        # it refuses hosts that do not resolve to a public address: the lookup is allowed, the
        # page itself still comes from ofapi through the proxy
        "STATICFIRE_NETWORK_ALLOW": "www.example.net",
    },
    enrich=_report,
    expected_types={"report"},
    calls=["/report-article-fetcher/news/"],
    description="an RSS-style report gets the body of the article its external reference links "
    "to written into its content (the connector sends the report back with its content filled)",
)
