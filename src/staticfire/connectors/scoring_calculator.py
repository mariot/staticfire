import uuid

from staticfire.connector_vendors import ConnectorSpec

LABEL = "[Scoring] High priority"


def _label_id(cti) -> str:
    found = cti.graphql(
        """query ($search: String) { labels(search: $search, first: 5) {
             edges { node { id value } } } }""",
        {"search": LABEL},
    )["labels"]["edges"]
    for edge in found:
        if edge["node"]["value"] == LABEL:
            return edge["node"]["id"]
    return cti.graphql(
        """mutation ($input: LabelAddInput!) { labelAdd(input: $input) { id } }""",
        {"input": {"value": LABEL, "color": "#ff0000"}},
    )["labelAdd"]["id"]


def _indicator_of_priority_threat(cti) -> str:
    """A fresh address indicator (score 80) that indicates a high priority intrusion set."""
    suffix = uuid.uuid4().int
    address = f"198.18.{suffix % 250 + 1}.{suffix // 250 % 250 + 1}"
    indicator = cti.create_indicator(address, f"[ipv4-addr:value = '{address}']", "IPv4-Addr")
    threat = cti.graphql(
        """mutation ($input: IntrusionSetAddInput!) { intrusionSetAdd(input: $input) { id } }""",
        {
            "input": {
                "name": f"staticfire-scoring-{uuid.uuid4().hex[:8]}",
                "objectLabel": [_label_id(cti)],
            }
        },
    )["intrusionSetAdd"]
    cti.graphql(
        """mutation ($input: StixCoreRelationshipAddInput!) {
             stixCoreRelationshipAdd(input: $input) { id } }""",
        {
            "input": {
                "fromId": indicator["id"],
                "toId": threat["id"],
                "relationship_type": "indicates",
            }
        },
    )
    return indicator["id"]


SPEC = ConnectorSpec(
    recipe="scoring-calculator",
    connector="internal-enrichment/scoring-calculator",
    env=lambda fake: {
        "CONNECTOR_SCORING_HIGH_PRIORITY_LABELS": f'["{LABEL}"]',
        "CONNECTOR_SCORING_THREAT_IMPACT_SCORE": "true",
        "CONNECTOR_SCORING_THREAT_HIGH_PRIORITY": "40",
    },
    enrich=_indicator_of_priority_threat,
    expected_types={"indicator"},
    calls=[],
    description="no vendor: an indicator (score 80) linked to an intrusion set labelled high "
    "priority (+40% of the margin) is sent back with a score of 88",
)
