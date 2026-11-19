from staticfire.connector_vendors import ConnectorSpec

SPEC = ConnectorSpec(
    recipe="disarm-framework",
    connector="external-import/disarm-framework",
    expected_types={
        "attack-pattern",
        "course-of-action",
        "intrusion-set",
        "campaign",
        "malware",
        "tool",
        "report",
        "narrative",
        "event",
        "channel",
        "relationship:uses",
        "relationship:mitigates",
    },
    calls=["/github/DISARMFoundation/DISARMframeworks/"],
    description="downloads the DISARM STIX bundle from GitHub (raw) and imports it, with the "
    "kill chain renamed to disarm",
)
