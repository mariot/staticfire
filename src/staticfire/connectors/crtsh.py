from staticfire.connector_vendors import ConnectorSpec

SPEC = ConnectorSpec(
    recipe="crtsh",
    connector="external-import/crtsh",
    env=lambda fake: {"CRTSH_DOMAIN": "example.com", "CRTSH_IS_WILDCARD": "true"},
    expected_types={"x509-certificate", "domain-name", "email-addr", "relationship:related-to"},
    calls=["/crtsh/"],
    description="the certificates of a domain become x509 certificates, domains and emails",
)
