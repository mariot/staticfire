from staticfire.connector_vendors import ConnectorSpec

SPEC = ConnectorSpec(
    recipe="tanium-intel",
    connector="stream/tanium-intel",
    env=lambda fake: {
        "TANIUM_INTEL_URL": "https://staticfire-api.cloud.tanium.com",
        "TANIUM_INTEL_URL_CONSOLE": "https://staticfire.cloud.tanium.com",
        "TANIUM_INTEL_TOKEN": "token-staticfire-fake-key",
    },
    calls=[
        "/cti-tanium/plugin/products/threat-response/api/v1/sources/",
        "/cti-tanium/plugin/products/threat-response/api/v1/intels/quick-add",
    ],
    description="a new STIX indicator becomes an intel document (converted to STIX 1) and a new "
    "address an OpenIOC one, both deployed and scanned, with the labels copied",
)
