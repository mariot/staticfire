from staticfire.connector_vendors import ConnectorSpec


def _env(fake) -> dict[str, str]:
    return {
        "DEP_USERNAME": "staticfire@example.com",
        "DEP_PASSWORD": "staticfire-fake-password",
        "DEP_API_KEY": "staticfire-fake-key",
        "DEP_CLIENT_ID": "staticfire-fake-client",
        # the real Cognito host belongs to another vendor's fake (SRP flow)
        "DEP_LOGIN_ENDPOINT": "https://cognito.digintlab.staticfire.test/",
    }


SPEC = ConnectorSpec(
    recipe="digintlab-dep",
    connector="external-import/digintlab-dep",
    env=_env,
    expected_types={
        "report",
        "identity",
        "indicator",
        "intrusion-set",
        "location",
        "relationship:related-to",
        "relationship:targets",
        "relationship:located-at",
    },
    calls=["/digintlab-dep/", "/digintlab-dep/v1/dbtr/privlist"],
    description="Cognito password login then the ransomware leak announcements become reports "
    "with victims, sectors, actors, countries and indicators",
)
