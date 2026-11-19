import uuid

from staticfire import config, ops
from staticfire.connector_vendors import ConnectorSpec

# Intrusion sets the attribution model is trained on, each with its own techniques
INTRUSION_SETS = {
    "staticfire APT-Alpha": ["T1566", "T1059", "T1547", "T1003"],
    "staticfire APT-Bravo": ["T1190", "T1505", "T1071", "T1041"],
    "staticfire APT-Charlie": ["T1078", "T1021", "T1486", "T1490"],
}


def _client():
    """OpenCTI of the current profile, or of the first saved one that holds it."""
    profile = config.load_profile()
    for name in config.list_profiles():
        if profile.opencti_url:
            break
        profile = config.load_profile(name)
    return ops.cti_client(profile)


def _uses(cti, source_id: str, technique: str) -> None:
    cti.add_uses_attack_pattern(source_id, technique, f"staticfire technique {technique}")


def _seed_training_data() -> None:
    """The connector trains its model from OpenCTI's intrusion sets as it starts."""
    cti = _client()
    for name, techniques in INTRUSION_SETS.items():
        intrusion_set = cti.create_intrusion_set(name)
        for technique in techniques:
            _uses(cti, intrusion_set["id"], technique)


def _env(fake) -> dict[str, str]:
    _seed_training_data()
    return {
        # a relationship for every ranked intrusion set, not only the confident ones
        "ATTRIBUTIONTOOLS_AUTOMATIC_RELATION_CREATION": "true",
        "ATTRIBUTIONTOOLS_RELATION_CREATION_PROBABILITY_TRESHOLD": "0.0",
    }


def _incident(cti) -> str:
    """An incident using the techniques of the first intrusion set."""
    incident = cti.graphql(
        """mutation ($input: IncidentAddInput!) { incidentAdd(input: $input) { id } }""",
        {"input": {"name": f"staticfire incident {uuid.uuid4().hex[:8]}"}},
    )["incidentAdd"]
    for technique in list(INTRUSION_SETS.values())[0][:3]:
        _uses(cti, incident["id"], technique)
    return incident["id"]


SPEC = ConnectorSpec(
    recipe="attribution-tools",
    connector="internal-enrichment/attribution-tools",
    env=_env,
    enrich=_incident,
    expected_types={"note", "relationship:attributed-to"},
    timeout=600,
    description="an incident is attributed to the intrusion sets of a model trained from OpenCTI",
)
