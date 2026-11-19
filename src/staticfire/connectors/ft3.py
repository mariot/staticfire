from staticfire.connector_vendors import ConnectorSpec

SPEC = ConnectorSpec(
    recipe="ft3",
    connector="external-import/ft3",
    # The connector's default scope: the compose file's CONNECTOR_SCOPE=ft3 makes the worker
    # drop the attack patterns (the scope is sent as the bundle's entity types)
    env=lambda fake: {
        "CONNECTOR_SCOPE": "identity,attack-pattern,x-mitre-tactic,x-opencti-kill-chain,"
        "marking-definition"
    },
    expected_types={
        "identity",
        "x-mitre-tactic",
        "attack-pattern",
        "x-opencti-kill-chain",
        "relationship:subtechnique-of",
    },
    calls=["/github/stripe/ft3/refs/heads/master/"],
    description="the Stripe FT3 tactics and techniques JSON files (served as raw GitHub files) "
    "become tactics, attack patterns and sub-technique relationships",
)
