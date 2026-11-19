from staticfire.connector_vendors import ConnectorSpec


def _env(fake) -> dict[str, str]:
    return {
        "CYBERSIXGILL_CLIENT_ID": "staticfire-client",
        "CYBERSIXGILL_CLIENT_SECRET": "staticfire-fake-secret",
        # sixgill-clients sends prepared requests with verify=True: certifi, not the CA variables
    }


SPEC = ConnectorSpec(
    recipe="cybersixgill",
    connector="external-import/cybersixgill",
    env=_env,
    expected_types={
        "indicator",
        "ipv4-addr",
        "domain-name",
        "url",
        "file",
        "identity",
        "relationship:based-on",
    },
    calls=["/cybersixgill/auth/token", "/cybersixgill/darkfeed/ioc"],
    description="the Darkfeed IOC batch (IP, domain, URL and file hash patterns) becomes "
    "observables and indicators",
)
