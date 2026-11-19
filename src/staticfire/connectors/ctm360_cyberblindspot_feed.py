from staticfire.connector_vendors import ConnectorSpec

SPEC = ConnectorSpec(
    recipe="ctm360-cyberblindspot-feed",
    connector="external-import/ctm360-cyberblindspot-feed",
    env=lambda fake: {
        "CTM360_CBS_API_KEY": "staticfire-fake-key",
        "CTM360_CBS_STATUS_POLL_INTERVAL": "3600",
    },
    expected_types={
        "indicator",
        "malware",
        "ipv4-addr",
        "domain-name",
        "email-addr",
        "user-account",
        "note",
        "relationship:uses",
        "relationship:based-on",
        "relationship:resolves-to",
    },
    calls=[
        "/ctm360-cbs/api/v2/incidents",
        "/ctm360-cbs/api/v2/leaks/malware_logs",
        "/ctm360-cbs/api/v2/leaks/breached_credentials",
        "/ctm360-cbs/api/v2/leaks/card_leaks",
        "/ctm360-cbs/api/v2/domain_protection",
    ],
    description="CBS incidents (case incidents), malware logs, leaks and typosquats become STIX",
)
