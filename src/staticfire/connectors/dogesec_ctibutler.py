from staticfire.connector_vendors import ConnectorSpec

SPEC = ConnectorSpec(
    recipe="dogesec-ctibutler",
    connector="external-import/dogesec-ctibutler",
    env=lambda fake: {
        "CTIBUTLER_API_KEY": "staticfire-fake-key",
        "CTIBUTLER_KNOWLEDGEBASES": "attack-enterprise,capec,location",
        "CTIBUTLER_INTERVAL_DAYS": "1",
    },
    expected_types={"attack-pattern", "intrusion-set", "location", "relationship:uses"},
    calls=[
        "/dogesec/v1/attack-enterprise/versions/installed/",
        "/dogesec/v1/capec/objects/",
        "/dogesec/v1/location/objects/",
    ],
    description="ATT&CK, CAPEC and location knowledge bases, one bundle per object",
)
