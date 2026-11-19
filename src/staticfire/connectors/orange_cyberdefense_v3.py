from datetime import UTC, datetime, timedelta

from staticfire.connector_vendors import ConnectorSpec


def _env(fake) -> dict[str, str]:
    start = (datetime.now(UTC) - timedelta(days=10)).strftime("%Y-%m-%d")
    queries = '[{"query_hash":"bb08a750538baea3e1c8cda0ae5b3aca","label":"high_confidence_iocs"}]'
    return {
        "OCD_DATALAKE_TOKEN": "staticfire-fake-key",
        "OCD_WORLDWATCH_API_KEY": "staticfire-fake-key",
        "OCD_DATALAKE_QUERIES": queries,
        "OCD_WORLDWATCH_START_DATE": start,
        "OCD_DATALAKE_ZIP_FILE_PATH": "/tmp/staticfire-ocd-data",
    }


SPEC = ConnectorSpec(
    recipe="orange-cyberdefense-v3",
    connector="external-import/orange-cyberdefense-v3",
    env=_env,
    expected_types={
        "indicator",
        "note",
        "malware",
        "intrusion-set",
        "sighting",
        "report",
        "relationship:indicates",
        "relationship:uses",
    },
    calls=[
        "/orange-cyberdefense/api/v3/users/me/",
        "/orange-cyberdefense/api/v3/mrti/threat-entity/filtered/",
        "/orange-cyberdefense/api/v3/mrti/bulk-search/",
        "/orange-cyberdefense/api/content_block/",
    ],
    timeout=600,
    description="Datalake bulk search indicators with notes, sightings and related threats, the "
    "threat library, and World Watch advisories as reports with their indicators and entities",
)
