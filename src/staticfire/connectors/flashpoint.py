from staticfire import config, ops
from staticfire.connector_vendors import ConnectorSpec

# Resolved by the connector from the tags and actors of the reports (ofapi flashpoint module)
KNOWN_ACTOR = "Staticfire Panda"
KNOWN_MALWARE = "StaticfireRAT"


def _env(fake) -> dict[str, str]:
    profile = config.load_profile()
    for name in config.list_profiles():
        if profile.opencti_url:
            break
        profile = config.load_profile(name)
    cti = ops.cti_client(profile)
    cti.create_intrusion_set(KNOWN_ACTOR)
    cti.graphql(
        """mutation ($input: MalwareAddInput!) { malwareAdd(input: $input) { id } }""",
        {"input": {"name": KNOWN_MALWARE, "is_family": True}},
    )
    return {
        "FLASHPOINT_API_KEY": "staticfire-fake-key",
        "FLASHPOINT_IMPORT_START_DATE": "P3D",
        "FLASHPOINT_IMPORT_REPORTS": "true",
        "FLASHPOINT_GUESS_RELATIONSHIPS_FROM_REPORTS": "true",
        "FLASHPOINT_IMPORT_INDICATORS": "true",
        "FLASHPOINT_IMPORT_EXTRACTED_CONFIG_DOMAINS_URLS": "true",
        "FLASHPOINT_IMPORT_ALERTS": "true",
        "FLASHPOINT_ALERT_CREATE_RELATED_ENTITIES": "true",
        "FLASHPOINT_IMPORT_COMMUNITIES": "true",
        "FLASHPOINT_IMPORT_CCM_ALERTS": "true",
    }


SPEC = ConnectorSpec(
    recipe="flashpoint",
    connector="external-import/flashpoint",
    env=_env,
    expected_types={
        "report",
        "indicator",
        "ipv4-addr",
        "ipv6-addr",
        "domain-name",
        "url",
        "file",
        "email-addr",
        "intrusion-set",
        "malware",
        "attack-pattern",
        "note",
        "incident",
        "channel",
        "user-account",
        "relationship:based-on",
        "relationship:indicates",
        "relationship:uses",
        "relationship:related-to",
        "relationship:communicates-with",
        "relationship:publishes",
    },
    calls=[
        "/flashpoint/finished-intelligence/v1/reports",
        "/flashpoint/technical-intelligence/v2/indicators",
        "/flashpoint/alert-management/v1/notifications",
        "/flashpoint/sources/v2/communities",
        "/flashpoint/sources/v1/noncommunities/search",
        "/flashpoint/sources/v1/noncommunities/scroll",
    ],
    timeout=600,
    description="reports, two pages of indicators (incl. extracted configs), alerts (communities, "
    "media, data exposure), communities search and scrolled compromised credentials; media "
    "files and report content are uploaded, not in the bundles",
)
