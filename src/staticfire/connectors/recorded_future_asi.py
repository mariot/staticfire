from staticfire.connector_vendors import ConnectorSpec

SPEC = ConnectorSpec(
    recipe="recorded-future-asi",
    connector="external-import/recorded-future-asi",
    env=lambda fake: {
        "RECORDED_FUTURE_ASI_API_KEY": "staticfire-fake-key",
        "RECORDED_FUTURE_ASI_PROJECT_ID": "staticfire-project",
    },
    expected_types={
        "incident",
        "vulnerability",
        "ipv4-addr",
        "ipv6-addr",
        "domain-name",
        "relationship:related-to",
    },
    calls=[
        "/recorded-future/v2/projects/staticfire-project/exposures",
    ],
    description="the project's exposures and their affected assets become incidents, "
    "observables and vulnerabilities",
)
