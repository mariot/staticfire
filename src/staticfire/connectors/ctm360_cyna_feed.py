from staticfire.connector_vendors import ConnectorSpec

SPEC = ConnectorSpec(
    recipe="ctm360-cyna-feed",
    connector="external-import/ctm360-cyna-feed",
    env=lambda fake: {"CTM360_CYNA_API_KEY": "staticfire-fake-key", "CTM360_CYNA_PAGE_SIZE": "3"},
    expected_types={"report", "vulnerability", "relationship:related-to"},
    calls=["/ctm360-cyna/api/v1/news"],
    description="cursor-paginated CYNA news become reports with the CVEs they mention",
)
