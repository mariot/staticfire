from staticfire.connector_vendors import ConnectorSpec

SPEC = ConnectorSpec(
    recipe="wiz",
    connector="external-import/wiz",
    env=lambda fake: {"WIZ_THREAT_ACTOR_AS_INTRUSION_SET": "false"},
    expected_types={"threat-actor", "malware", "tool", "attack-pattern", "relationship:uses"},
    calls=["/wiz/api/feed/cloud-threat-landscape/stix.json"],
    description="the public cloud threat landscape STIX feed: actors, malware, tools, techniques",
)
