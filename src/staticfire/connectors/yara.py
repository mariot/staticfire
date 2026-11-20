import uuid

from staticfire.connector_vendors import ConnectorSpec

MARKER = "staticfire-yara-marker"
RULE = f'rule staticfire_yara {{ strings: $a = "{MARKER}" condition: $a }}'


def _seed_rule(cti) -> None:
    """A YARA indicator with a label, indicating a malware."""
    indicator = cti.create_indicator(
        "staticfire_yara", RULE, "StixFile", pattern_type="yara", labels=["staticfire-yara"]
    )
    malware = cti.graphql(
        "mutation ($input: MalwareAddInput!) { malwareAdd(input: $input) { id } }",
        {"input": {"name": "StaticfireYaraMalware", "is_family": True}},
    )["malwareAdd"]["id"]
    cti.graphql(
        """mutation ($input: StixCoreRelationshipAddInput!) {
             stixCoreRelationshipAdd(input: $input) { id } }""",
        {
            "input": {
                "fromId": indicator["id"],
                "toId": malware,
                "relationship_type": "indicates",
            }
        },
    )


def _artifact(cti) -> str:
    content = f"MZ\x90\x00 {MARKER} {uuid.uuid4().hex}".encode()
    return cti.create_artifact(content, "staticfire-sample.bin", "application/octet-stream")


SPEC = ConnectorSpec(
    recipe="yara",
    connector="internal-enrichment/yara",
    env=lambda fake: {
        "YARA_PROPAGATE_MALWARE_RELATIONSHIP": "true",
        "YARA_PROPAGATE_LABELS": "true",
    },
    prepare=_seed_rule,
    enrich=_artifact,
    expected_types={"indicator", "malware", "relationship:related-to"},
    description="an Artifact's file is scanned with the YARA rules stored in OpenCTI (no vendor "
    "call): related-to the matching rule and, through it, the malware it indicates",
)
