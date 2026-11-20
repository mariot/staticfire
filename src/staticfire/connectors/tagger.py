import uuid

from staticfire.connector_vendors import ConnectorSpec

# the report created for the run, checked afterwards
_REPORT: dict[str, str] = {}


def _cloud_report(cti) -> str:
    """A report whose name matches the "cloud" rule of the compose file's definitions."""
    _REPORT["id"] = cti.graphql(
        """mutation ($name: String!, $published: DateTime!) {
             reportAdd(input: { name: $name, published: $published }) { id } }""",
        {
            "name": f"staticfire tagger Cloud intrusion {uuid.uuid4().hex[:8]}",
            "published": "2026-01-01T00:00:00.000Z",
        },
    )["reportAdd"]["id"]
    return _REPORT["id"]


def _labelled(cti) -> list[tuple[str, bool, object]]:
    labels = cti.graphql(
        "query ($id: String!) { report(id: $id) { objectLabel { value } } }", {"id": _REPORT["id"]}
    )["report"]["objectLabel"]
    values = [label["value"].lower() for label in labels]
    return [("the report got the 'cloud' label", "cloud" in values, values)]


SPEC = ConnectorSpec(
    recipe="tagger",
    connector="internal-enrichment/tagger",
    enrich=_cloud_report,
    calls=[],
    verify=_labelled,
    description="no vendor: a report whose name matches the 'cloud' rule gets that label through "
    "the API (checked in OpenCTI; no bundle is sent)",
)
