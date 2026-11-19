from staticfire.connector_vendors import ConnectorSpec

COMMON = {
    "CRITS_URL": "https://crits.staticfire.test",
    "CRITS_API_KEY": "staticfire-fake-key",
    "CRITS_CHUNK_SIZE": "3",
}

SPECS = [
    ConnectorSpec(
        recipe="crits",
        connector="external-import/crits",
        env=lambda fake: {**COMMON, "CRITS_USER": "staticfire"},
        expected_types={
            "ipv4-addr",
            "ipv6-addr",
            "domain-name",
            "file",
            "text",
            "threat-actor",
            "intrusion-set",
            "malware",
            "indicator",
            "identity",
            "email-message",
            "relationship:related-to",
        },
        calls=["/crits/api/v1/ips/", "/crits/api/v1/samples/", "/crits/api/v1/targets/"],
        description="every CRITs collection, paged by 3, becomes entities, observables, indicators",
    ),
    ConnectorSpec(
        recipe="crits-events",
        connector="external-import/crits",
        env=lambda fake: {**COMMON, "CRITS_USER": "staticfire-events"},
        expected_types={"report", "ipv4-addr", "domain-name", "file", "campaign"},
        calls=["/crits/api/v1/events/"],
        description="a CRITs event with related IP, domain and sample becomes a report of them",
    ),
]
