import uuid

from staticfire.connector_vendors import ConnectorSpec


def _report(cti) -> tuple[str, str]:
    indicator = cti.create_indicator(
        f"staticfire pdf {uuid.uuid4().hex[:8]}", "[ipv4-addr:value = '198.51.100.9']", "IPv4-Addr"
    )
    report = cti.create_report(f"staticfire report {uuid.uuid4().hex[:8]}", [indicator["id"]])
    return report["id"], "Report"


SPEC = ConnectorSpec(
    recipe="export-report-pdf",
    connector="internal-export-file/export-report-pdf",
    export=("application/pdf", "entity"),
    export_object=_report,
    description="a report holding an indicator is exported as a PDF",
)
