import json
import uuid
from datetime import UTC, datetime, timedelta

from staticfire import config, ops
from staticfire.connector_vendors import ConnectorSpec

LABEL = "staticfire-defender-sync"
COLLECTION = "staticfire defender-intel-synchronizer"
ROLE = "staticfire data sharing"


def _cti():
    """An admin client of the first saved profile holding an OpenCTI platform."""
    for name in config.list_profiles():
        profile = config.load_profile(name)
        if profile.opencti_url:
            return ops.cti_client(profile)
    raise ValueError("no profile with an OpenCTI platform")


def _collection_id(cti) -> str:
    """The id of the TAXII collection of the test's indicators (created once): the
    synchronizer reads what a TAXII collection of OpenCTI shares, named by its id."""
    edges = cti.graphql(
        """query ($search: String) { taxiiCollections(search: $search) {
             edges { node { id name } } } }""",
        {"search": COLLECTION},
    )["taxiiCollections"]["edges"]
    if found := next((e["node"]["id"] for e in edges if e["node"]["name"] == COLLECTION), None):
        return found
    filters = {
        "mode": "and",
        "filters": [
            {"key": ["entity_type"], "values": ["Indicator"], "operator": "eq", "mode": "or"},
            {"key": ["objectLabel"], "values": [cti.label(LABEL)], "operator": "eq", "mode": "or"},
        ],
        "filterGroups": [],
    }
    return cti.graphql(
        """mutation ($input: TaxiiCollectionAddInput!) {
             taxiiCollectionAdd(input: $input) { id } }""",
        {
            "input": {
                "name": COLLECTION,
                "description": "staticfire",
                "filters": json.dumps(filters),
                "taxii_public": False,
                "authorized_members": [],
            }
        },
    )["taxiiCollectionAdd"]["id"]


def _grant_data_sharing(cti, user_name: str) -> None:
    """Put the connector's account in a group allowed to read TAXII collections ("Manage
    data sharing": the synchronizer asks OpenCTI for the filters of its collections)."""
    role = group = None
    if found := _named(cti, "roles", ROLE):
        role = found
    else:
        role = cti.graphql(
            "mutation ($input: RoleAddInput!) { roleAdd(input: $input) { id } }",
            {"input": {"name": ROLE, "description": "staticfire"}},
        )["roleAdd"]["id"]
        capabilities = cti.graphql("{ capabilities(first: 300) { edges { node { id name } } } }")[
            "capabilities"
        ]["edges"]
        for edge in capabilities:
            if edge["node"]["name"] in ("KNOWLEDGE", "TAXIIAPI", "TAXIIAPI_SETCOLLECTIONS"):
                cti.graphql(
                    """mutation ($id: ID!, $input: InternalRelationshipAddInput!) {
                         roleEdit(id: $id) { relationAdd(input: $input) { id } } }""",
                    {
                        "id": role,
                        "input": {
                            "toId": edge["node"]["id"],
                            "relationship_type": "has-capability",
                        },
                    },
                )
    if found := _named(cti, "groups", ROLE):
        group = found
    else:
        group = cti.graphql(
            "mutation ($input: GroupAddInput!) { groupAdd(input: $input) { id } }",
            {
                "input": {
                    "name": ROLE,
                    "description": "staticfire",
                    "group_confidence_level": {"max_confidence": 100, "overrides": []},
                }
            },
        )["groupAdd"]["id"]
        cti.graphql(
            """mutation ($id: ID!, $input: InternalRelationshipAddInput!) {
                 groupEdit(id: $id) { relationAdd(input: $input) { id } } }""",
            {"id": group, "input": {"toId": role, "relationship_type": "has-role"}},
        )
    user = cti.user_by_name(user_name)
    members = cti.graphql(
        """query ($id: String!) { user(id: $id) { groups { edges { node { id } } } } }""",
        {"id": user["id"]},
    )["user"]["groups"]["edges"]
    if group not in [e["node"]["id"] for e in members]:
        cti.graphql(
            """mutation ($id: ID!, $input: InternalRelationshipAddInput!) {
                 userEdit(id: $id) { relationAdd(input: $input) { id } } }""",
            {"id": user["id"], "input": {"toId": group, "relationship_type": "member-of"}},
        )


def _named(cti, kind: str, name: str) -> str | None:
    edges = cti.graphql(
        f"query ($search: String) {{ {kind}(search: $search) {{ "
        "edges { node { id name } } } }",
        {"search": name},
    )[kind]["edges"]
    return next((e["node"]["id"] for e in edges if e["node"]["name"] == name), None)


def _env(fake) -> dict[str, str]:
    cti = _cti()
    _grant_data_sharing(cti, "staticfire-microsoft-defender-intel-synchronizer")
    collection = _collection_id(cti)
    return {
        "MICROSOFT_DEFENDER_INTEL_SYNCHRONIZER_TENANT_ID": "0b9a2c6e-6d1f-4c0e-9a57-3f2f1d7c8e11",
        "MICROSOFT_DEFENDER_INTEL_SYNCHRONIZER_CLIENT_ID": "5c1d7e2a-33b4-4e0a-8f6d-9a1b2c3d4e5f",
        "MICROSOFT_DEFENDER_INTEL_SYNCHRONIZER_CLIENT_SECRET": "staticfire-fake-secret",
        "MICROSOFT_DEFENDER_INTEL_SYNCHRONIZER_TAXII_COLLECTIONS": json.dumps(
            {collection: {"action": "Block", "expire_time": 7, "rbac_group_names": ["Production"]}}
        ),
        "MICROSOFT_DEFENDER_INTEL_SYNCHRONIZER_RBAC_GROUP_NAMES": '["Default Group"]',
        "MICROSOFT_DEFENDER_INTEL_SYNCHRONIZER_INTERVAL": "20",
    }


def _indicators(cti) -> list[str]:
    """Labelled indicators (shared by the TAXII collection) on a new domain, IPv4 address
    and URL; the domain and the address are the markers."""
    token = uuid.uuid4().hex
    domain = f"sf-{token[:8]}.sync.example.com"
    ip = f"198.51.{int(token[8:10], 16) % 256}.{int(token[10:12], 16) % 254 + 1}"
    url = f"https://sf-{token[:8]}.sync.example.com/payload.bin"
    label = cti.label(LABEL)
    valid_until = (datetime.now(UTC) + timedelta(days=30)).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    for main_type, pattern in (
        ("Domain-Name", f"[domain-name:value = '{domain}']"),
        ("IPv4-Addr", f"[ipv4-addr:value = '{ip}']"),
        ("Url", f"[url:value = '{url}']"),
    ):
        cti.graphql(
            """mutation ($input: IndicatorAddInput!) { indicatorAdd(input: $input) { id } }""",
            {
                "input": {
                    "name": f"staticfire sync {pattern}",
                    "pattern": pattern,
                    "pattern_type": "stix",
                    "x_opencti_main_observable_type": main_type,
                    "x_opencti_score": 80,
                    "valid_until": valid_until,
                    "objectLabel": [label],
                }
            },
        )
    return [domain, ip]


SPEC = ConnectorSpec(
    recipe="microsoft-defender-intel-synchronizer",
    connector="stream/microsoft-defender-intel-synchronizer",
    env=_env,
    stream=_indicators,
    calls=["/microsoft-defender/api/indicators/import"],
    description="the indicators of a TAXII collection (domain, IPv4, URL) are synchronized "
    "to Defender with the collection's action, expiration and RBAC groups (the connector "
    "polls every 20 s)",
)
