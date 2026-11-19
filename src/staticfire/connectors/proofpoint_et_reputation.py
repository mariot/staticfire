from staticfire.connector_vendors import ConnectorSpec

SPEC = ConnectorSpec(
    recipe="proofpoint-et-reputation",
    connector="external-import/proofpoint-et-reputation",
    env=lambda fake: {"PROOFPOINT_ET_REPUTATION_API_TOKEN": "staticfire-fake-key"},
    expected_types={"ipv4-addr", "domain-name", "indicator", "relationship:based-on"},
    calls=[
        "/proofpoint-et/staticfire-fake-key/reputation/iprepdata.json",
        "/proofpoint-et/staticfire-fake-key/reputation/domainrepdata.json",
    ],
    description="the IP and domain reputation lists become scored observables and indicators",
)
