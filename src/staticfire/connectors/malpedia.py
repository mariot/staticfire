from staticfire.connector_vendors import ConnectorSpec

SPEC = ConnectorSpec(
    recipe="malpedia",
    connector="external-import/malpedia",
    env=lambda fake: {"MALPEDIA_AUTH_KEY": "staticfire-fake-key"},
    expected_types={
        "malware",
        "indicator",
        "file",
        "intrusion-set",
        "location",
        "relationship:indicates",
        "relationship:uses",
        "relationship:originates-from",
    },
    calls=["/malpedia/api/get/families", "/malpedia/api/get/actor/"],
    description="authenticated import: families with YARA rules, samples and attributed actors",
)
