from staticfire.connector_vendors import ConnectorSpec

SPEC = ConnectorSpec(
    recipe="trellix-tie",
    connector="stream/trellix-tie",
    blocked=(
        "the connector talks to Trellix TIE over an OpenDXL fabric (dxlclient: MQTT over TLS to a "
        "DXL broker with mutual-TLS certificates from an ePO-provisioned dxlclient.config, then "
        "DXL binary request/response messages to the TIE reputation service), not HTTP: it never "
        "uses the proxy, and a fake needs a TLS MQTT broker speaking the DXL message format, "
        "which ofapi (HTTP only) cannot host"
    ),
    description="file hashes of indicators from the stream become TIE reputations",
)
