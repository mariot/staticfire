from staticfire.connector_vendors import ConnectorSpec

SPEC = ConnectorSpec(
    recipe="crowdsec-import",
    connector="external-import/crowdsec-import",
    env=lambda fake: {
        "CROWDSEC_KEY": "staticfire-fake-key",
        "CROWDSEC_CREATE_TARGETED_COUNTRIES_SIGHTINGS": "true",
        "CROWDSEC_IMPORT_QUERY_SINCE": "24",
    },
    expected_types={
        "ipv4-addr",
        "indicator",
        "attack-pattern",
        "vulnerability",
        "location",
        "note",
        "sighting",
        "relationship:based-on",
        "relationship:indicates",
        "relationship:targets",
    },
    calls=["/crowdsec/v2/smoke/search"],
    description="paged smoke search IPs become observables, indicators, MITRE, CVEs, countries",
)
