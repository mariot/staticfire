from staticfire.connector_vendors import ConnectorSpec

SPEC = ConnectorSpec(
    recipe="sublime",
    connector="external-import/sublime",
    env=lambda fake: {"SUBLIME_TOKEN": "staticfire-fake-key"},
    expected_types={
        "incident",
        "email-message",
        "email-addr",
        "url",
        "domain-name",
        "ipv4-addr",
        "file",
        "indicator",
        "relationship:related-to",
    },
    calls=["/sublime/v1/messages/groups"],
    description="flagged malicious message groups (the benign one is skipped) become incidents "
    "with their email, addresses, URLs, domains, IPs, attachments and indicators",
)
