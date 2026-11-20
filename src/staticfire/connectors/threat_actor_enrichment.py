"""The connector calls no vendor: it reads threat actor groups, their malware, and the
indicators and reports about it, then sets the group's last_seen. The test seeds such a
group (created by the connector's own account, before its run) and judges the run on the
group being updated, since the connector's account then shows it among its changes."""

import json
import uuid

from staticfire import config
from staticfire.connector_vendors import ConnectorSpec
from staticfire.opencti import OpenCTI

ACCOUNT = "staticfire-threat-actor-enrichment"


def _client() -> OpenCTI:
    profile = next(p for p in map(config.load_profile, config.list_profiles()) if p.opencti_url)
    store = config.STATE_DIR / "opencti-users.json"
    known = json.loads(store.read_text()).get(f"{profile.opencti_url}|{ACCOUNT}")
    return OpenCTI(profile.opencti_url, known["token"] if known else profile.opencti_token)


def _seed(fake) -> dict[str, str]:
    """A group using a malware that an indicator and a report are about."""
    cti = _client()
    token = uuid.uuid4().hex[:8]

    def create(mutation: str, entity: str, **fields) -> str:
        query = f"mutation ($input: {entity}AddInput!) {{ {mutation}(input: $input) {{ id }} }}"
        return cti.graphql(query, {"input": fields})[mutation]["id"]

    actor = create("threatActorGroupAdd", "ThreatActorGroup", name=f"staticfire actor {token}")
    malware = create("malwareAdd", "Malware", name=f"staticfire malware {token}")
    indicator = create(
        "indicatorAdd",
        "Indicator",
        name=f"198.51.100.{int(token[:2], 16) % 250 + 1}",
        pattern=f"[ipv4-addr:value = '198.51.100.{int(token[:2], 16) % 250 + 1}']",
        pattern_type="stix",
        x_opencti_main_observable_type="IPv4-Addr",
        valid_from="2026-11-05T10:00:00.000Z",
    )
    create(
        "reportAdd",
        "Report",
        name=f"staticfire report {token}",
        published="2026-11-10T08:00:00.000Z",
        objects=[malware],
    )
    for source, target, kind in ((actor, malware, "uses"), (indicator, malware, "indicates")):
        create(
            "stixCoreRelationshipAdd",
            "StixCoreRelationship",
            fromId=source,
            toId=target,
            relationship_type=kind,
        )
    return {}


SPEC = ConnectorSpec(
    recipe="threat-actor-enrichment",
    connector="external-import/threat-actor-enrichment",
    env=_seed,
    opens_work=False,
    expected_types={"threat-actor-group"},
    description="a threat actor group using a malware, with an indicator and a report about "
    "it, gets its last_seen set from them (reads OpenCTI only, no vendor)",
)
