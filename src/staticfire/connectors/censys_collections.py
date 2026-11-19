from staticfire.connector_vendors import ConnectorSpec

SPEC = ConnectorSpec(
    recipe="censys-collections",
    connector="external-import/censys-collections",
    env=lambda fake: {
        "CENSYS_COLLECTIONS_ORGANISATION_ID": "staticfire-org",
        "CENSYS_COLLECTIONS_TOKEN": "staticfire-fake-key",
        # every observable asks OpenCTI for an indicator, whatever its score
        "CENSYS_COLLECTIONS_AUTO_INDICATOR_BY_SCORE": "false",
    },
    expected_types={
        "ipv4-addr",
        "domain-name",
        "x509-certificate",
        "malware",
        "threat-actor",
        "vulnerability",
        "grouping",
        "relationship:related-to",
    },
    calls=["/censys-platform/v3/collections"],
    description="collection assets (hosts, web properties, certificates) become observables",
)
