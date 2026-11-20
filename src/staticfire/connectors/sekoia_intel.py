from staticfire.connector_vendors import ConnectorSpec

SPEC = ConnectorSpec(
    recipe="sekoia-intel",
    connector="stream/sekoia-intel",
    env=lambda fake: {
        "SEKOIA_INTEL_URL": "https://api.sekoia.io/v2/inthreat/collections",
        "SEKOIA_INTEL_APIKEY": "staticfire-fake-key",
        "SEKOIA_INTEL_IOC_COLLECTION_UUID": "d6092c37-d8d7-45c3-8aff-c4dc26030608",
    },
    calls=["/sekoia/v2/inthreat/collections/"],
    description="indicators of the stream are parsed and imported as text IOCs of the collection",
)
