import time
import uuid

from staticfire import fakes
from staticfire.connector_vendors import ConnectorSpec

AUTHOR = "Malanta.ai"


def _label(cti, value: str) -> str:
    found = cti.graphql(
        "query ($s: String) { labels(search: $s) { edges { node { id value } } } }",
        {"s": value},
    )["labels"]["edges"]
    if label := next((e["node"]["id"] for e in found if e["node"]["value"] == value), None):
        return label
    return cti.graphql(
        "mutation ($input: LabelAddInput!) { labelAdd(input: $input) { id } }",
        {"input": {"value": value, "color": "#ff9800"}},
    )["labelAdd"]["id"]


def _attributed_indicator(cti) -> list[str]:
    """An indicator by the feed's author labelled ``apt:<actor>``, then what the connector,
    which calls no vendor, must write back: an intrusion set of that name and an ``indicates``
    relationship from the indicator. Once both exist in OpenCTI the test records them in ofapi,
    where the stream recipe looks for its markers."""
    author = cti.graphql(
        """mutation ($input: OrganizationAddInput!) { organizationAdd(input: $input) { id } }""",
        {"input": {"name": AUTHOR}},
    )["organizationAdd"]["id"]
    actor = f"StaticfireActor{uuid.uuid4().hex[:8]}"
    domain = f"sf-{uuid.uuid4().hex[:8]}.example.com"
    indicator = cti.graphql(
        """mutation ($input: IndicatorAddInput!) { indicatorAdd(input: $input) { id } }""",
        {
            "input": {
                "name": f"staticfire {domain}",
                "pattern": f"[domain-name:value = '{domain}']",
                "pattern_type": "stix",
                "x_opencti_main_observable_type": "Domain-Name",
                "createdBy": author,
                "objectLabel": [_label(cti, "IOC"), _label(cti, f"apt:{actor}")],
            }
        },
    )["indicatorAdd"]["id"]

    def intrusion_set() -> str | None:
        found = cti.graphql(
            """query ($search: String) { intrusionSets(search: $search) {
                 edges { node { id name } } } }""",
            {"search": actor},
        )["intrusionSets"]["edges"]
        if not found:
            return None
        linked = cti.graphql(
            """query ($id: [String]) { stixCoreRelationships(fromId: $id,
                 relationship_type: "indicates") { edges { node {
                   to { ... on BasicObject { id } } } } } }""",
            {"id": [indicator]},
        )["stixCoreRelationships"]["edges"]
        target = found[0]["node"]["id"]
        return target if any(e["node"]["to"]["id"] == target for e in linked) else None

    deadline = time.time() + 120
    while time.time() < deadline and not (found := intrusion_set()):
        time.sleep(5)
    if found:
        fakes.ofapi_up().http.post(
            "/malanta/verified", json={"actor": actor, "intrusion_set": found}
        )
    return [actor]


SPEC = ConnectorSpec(
    recipe="malanta-attribution",
    connector="stream/malanta-attribution",
    stream=_attributed_indicator,
    calls=["/malanta/verified"],
    description="an indicator by Malanta.ai labelled apt:<actor> gets an intrusion set and an "
    "indicates relationship (no vendor: the test checks OpenCTI and records it in ofapi)",
)
