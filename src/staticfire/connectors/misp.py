from staticfire.connector_vendors import ConnectorSpec

SPEC = ConnectorSpec(
    recipe="misp",
    connector="external-import/misp",
    env=lambda fake: {
        "MISP_URL": "https://misp.staticfire.test",
        "MISP_KEY": "staticfire-fake-key",
        "MISP_CREATE_OBJECT_OBSERVABLES": "true",
        "MISP_GUESS_THREATS_FROM_TAGS": "true",
    },
    expected_types={
        "report",
        "indicator",
        "domain-name",
        "ipv4-addr",
        "url",
        "email-addr",
        "intrusion-set",
        "malware",
        "attack-pattern",
        "location",
        "identity",
        "relationship:indicates",
        "relationship:related-to",
        "relationship:uses",
    },
    calls=["/misp/events/restSearch"],
    description="MISP events (galaxies, tags, attributes, objects, event report) found by the "
    "restSearch API become reports with indicators, observables and threat entities",
)
