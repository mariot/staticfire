from staticfire.connector_vendors import ConnectorSpec

SPEC = ConnectorSpec(
    recipe="cofense",
    connector="external-import/cofense",
    env=lambda fake: {
        "COFENSEINTEL_USER": "staticfire-user",
        "COFENSEINTEL_PASSWORD": "staticfire-fake-key",
    },
    expected_types={
        "incident",
        "file",
        "url",
        "ipv4-addr",
        "domain-name",
        "email-addr",
        "relationship:related-to",
        "identity",
    },
    calls=["/cofense-threathq/apiv1/threat/updates", "/cofense-threathq/apiv1/threat/search"],
    description="the threat update log and the searched malware threat reports become "
    "incidents related to their observables",
)
