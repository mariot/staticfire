from staticfire.connector_vendors import ConnectorSpec

_ENV = {
    "THEHIVE_URL": "https://thehive.staticfire.test",
    "THEHIVE_API_KEY": "staticfire-fake-key",
    "THEHIVE_ORGANIZATION_NAME": "Staticfire SOC",
    "THEHIVE_IMPORT_FROM_DATE": "2026-11-01T00:00:00",
}
_TYPES = {
    "incident",
    "case-incident",
    "task",
    "note",
    "ipv4-addr",
    "domain-name",
    "url",
    "file",
    "email-addr",
    "vulnerability",
    "autonomous-system",
    "sighting",
    "relationship:related-to",
}

SPECS = [
    ConnectorSpec(
        recipe="thehive",
        connector="external-import/thehive",
        env=lambda fake: _ENV,
        expected_types=_TYPES,
        min_elements=10,
        calls=["/thehive/api/v1/query"],
        description="cases (with observables, tasks and comments) and alerts become case "
        "incidents, incidents, observables, sightings, tasks and notes",
    ),
    ConnectorSpec(
        recipe="thehive-attachments",
        connector="external-import/thehive",
        env=lambda fake: {**_ENV, "THEHIVE_IMPORT_ATTACHMENTS": "true"},
        expected_types=_TYPES | {"artifact"},
        min_elements=10,
        calls=["/thehive/api/v1/query", "/thehive/api/v1/attachment/"],
        description="the same with attachments: each downloaded file becomes an Artifact "
        "in the bundle and a file of the case",
    ),
]
