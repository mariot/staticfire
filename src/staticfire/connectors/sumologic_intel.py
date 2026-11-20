from staticfire.connector_vendors import ConnectorSpec

SPEC = ConnectorSpec(
    recipe="sumologic-intel",
    connector="stream/sumologic-intel",
    env=lambda fake: {
        "SUMOLOGIC_INTEL_API_BASE_URL": "https://api.eu.sumologic.com",
        "SUMOLOGIC_INTEL_ACCESS_ID": "staticfire-access-id",
        "SUMOLOGIC_INTEL_ACCESS_KEY": "staticfire-fake-key",
    },
    calls=["/sumologic/api/v1/threatIntel/datastore/indicators/stix"],
    description="a new STIX indicator is uploaded to the threat intelligence datastore (the "
    "observable of the same stream is reported unsupported)",
)
