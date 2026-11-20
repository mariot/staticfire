from staticfire.connector_vendors import ConnectorSpec

SPEC = ConnectorSpec(
    recipe="vxvault",
    connector="external-import/vxvault",
    env=lambda fake: {"VXVAULT_CREATE_INDICATORS": "true"},
    expected_types={"url", "identity"},
    calls=["/vxvault/URL_List.php"],
    description="the URL list becomes URL observables (OpenCTI derives the indicators)",
)
