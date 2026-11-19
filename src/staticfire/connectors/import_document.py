from staticfire.connector_vendors import ConnectorSpec

SPECS = [
    ConnectorSpec(
        recipe="import-document",
        connector="internal-import-file/import-document",
        import_file=("staticfire-report.pdf", "/fixtures/report.pdf", "application/pdf"),
        expected_types={"report", "ipv4-addr", "domain-name", "file", "url"},
        description="a PDF report's observables are extracted (CVEs link only if known)",
    ),
    ConnectorSpec(
        recipe="import-document-text",
        connector="internal-import-file/import-document",
        import_file=("staticfire-report.txt", "/fixtures/report.txt", "text/plain"),
        expected_types={"report", "ipv4-addr", "domain-name", "file", "url"},
        description="the same from a plain text report",
    ),
]
