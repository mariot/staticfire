from staticfire.connector_vendors import ConnectorSpec

SPEC = ConnectorSpec(
    recipe="dogesec-siemrules",
    connector="external-import/dogesec-siemrules",
    env=lambda fake: {
        "SIEMRULES_API_KEY": "staticfire-fake-key",
        "SIEMRULES_DETECTION_PACKS": "f2a8c6e1-9b74-5d3c-a1e5-7c0b4d8e3f26",
        "SIEMRULES_INTERVAL_HOURS": "1",
    },
    expected_types={"indicator", "attack-pattern", "relationship:indicates"},
    calls=["/dogesec/v1/detection-packs/", "/dogesec/v1/base-rules/"],
    description="the base and correlation rules of a pack become Sigma indicators",
)
