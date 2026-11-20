import uuid

from staticfire.connector_vendors import ConnectorSpec

SPEC = ConnectorSpec(
    recipe="unpac-me",
    connector="internal-enrichment/unpac-me",
    env=lambda fake: {"UNPAC_ME_API_KEY": "staticfire-fake-key"},
    enrich=lambda cti: cti.create_artifact(f"MZ staticfire {uuid.uuid4()}".encode(), "sample.exe"),
    expected_types={"relationship:related-to"},
    calls=[
        "/unpac-me/api/v1/private/upload",
        "/unpac-me/api/v1/public/results/",
        "/unpac-me/api/v1/private/download/",
    ],
    description="an artifact's file is unpacked; the unpacked files are downloaded and uploaded "
    "as artifacts (through the API, not in the bundle) related to it, with family labels",
)
