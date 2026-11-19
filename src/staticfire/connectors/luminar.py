from datetime import UTC, datetime, timedelta

from staticfire.connector_vendors import ConnectorSpec


def _env(fake) -> dict[str, str]:
    since = datetime.now(UTC) - timedelta(days=5)
    return {
        "LUMINAR_ACCOUNT_ID": "staticfire-account",
        "LUMINAR_CLIENT_ID": "staticfire-client",
        "LUMINAR_CLIENT_SECRET": "staticfire-fake-secret",
        "LUMINAR_INITIAL_FETCH_DATE": since.strftime("%Y-%m-%d"),
        "LUMINAR_CREATE_OBSERVABLE": "true",
    }


SPEC = ConnectorSpec(
    recipe="luminar",
    connector="external-import/luminar",
    env=_env,
    expected_types={
        "malware",
        "threat-actor",
        "indicator",
        "ipv4-addr",
        "domain-name",
        "url",
        "file",
        "incident",
        "user-account",
        "vulnerability",
        "location",
        "report",
        "relationship:indicates",
        "relationship:based-on",
    },
    calls=[
        "/luminar/externalApi/v2/realm/",
        "/luminar/externalApi/taxii/collections/",
    ],
    description="IOCs (paged), leaked credentials and cyberfeed reports from the three TAXII "
    "collections, with observables created from the indicators",
)
