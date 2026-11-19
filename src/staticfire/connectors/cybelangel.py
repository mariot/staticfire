from staticfire.connector_vendors import ConnectorSpec


def _env(fake) -> dict[str, str]:
    return {
        "CYBELANGEL_CLIENT_ID": "staticfire-client",
        "CYBELANGEL_CLIENT_SECRET": "staticfire-fake-secret",
        "CYBELANGEL_FETCH_PERIOD": "7",
    }


SPEC = ConnectorSpec(
    recipe="cybelangel",
    connector="external-import/cybelangel",
    env=_env,
    expected_types={
        "campaign",
        "intrusion-set",
        "location",
        "identity",
        "relationship:targets",
        "relationship:attributed-to",
    },
    calls=["/cybelangel/oauth/token", "/cybelangel/api/v1/threat-intelligence/claimed-attacks"],
    description="OAuth2 login then the claimed attacks become campaigns, actors, victims, "
    "countries and sectors",
)
