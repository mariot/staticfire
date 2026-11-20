from staticfire.connector_vendors import ConnectorSpec

SPEC = ConnectorSpec(
    recipe="sekoia",
    connector="external-import/sekoia",
    env=lambda fake: {
        "SEKOIA_API_KEY": "staticfire-fake-key",
        "SEKOIA_LIMIT": "50",
    },
    expected_types={
        "indicator",
        "malware",
        "intrusion-set",
        "attack-pattern",
        "vulnerability",
        "report",
        "relationship:indicates",
        "relationship:uses",
    },
    calls=[
        "/sekoia/v2/inthreat/collections/",
        "/sekoia/v2/inthreat/objects/",
    ],
    description="the InThreat collection page with referenced identities, markings, "
    "indicator relationships and source labels (a report's file is uploaded through the API)",
)
