from datetime import UTC, datetime, timedelta

from staticfire.connector_vendors import ConnectorSpec


def _start_date() -> str:
    """Yesterday: the connector needs a whole day to process and waits a minute per day."""
    return (datetime.now(UTC) - timedelta(days=1)).strftime("%Y-%m-%d")


SPEC = ConnectorSpec(
    recipe="opencsam",
    connector="external-import/opencsam",
    env=lambda fake: {
        "OPENCSAM_API_URL": "https://api.opencsam.com",
        "OPENCSAM_API_KEY": "staticfire-fake-key",
        "OPENCSAM_ORGANIZATION": "OpenCSAM",
        "OPENCSAM_IMPORT_START_DATE": _start_date(),
    },
    expected_types={"incident", "identity", "report"},
    calls=["/opencsam/search/"],
    description="one day of threat news becomes incidents per source and a daily digest report",
)
