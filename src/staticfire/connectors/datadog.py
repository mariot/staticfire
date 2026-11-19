from datetime import UTC, datetime, timedelta

from staticfire.connector_vendors import ConnectorSpec


def _env(fake) -> dict[str, str]:
    return {
        "DATADOG_TOKEN": "staticfire-fake-key",
        "DATADOG_APP_KEY": "staticfire-fake-app-key",
        "DATADOG_IMPORT_START_DATE": (datetime.now(UTC) - timedelta(days=2)).strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        ),
        # smaller than the fake's signals: the connector follows the page cursor
        "DATADOG_BATCH_SIZE": "3",
    }


SPEC = ConnectorSpec(
    recipe="datadog",
    connector="external-import/datadog",
    env=_env,
    expected_types={
        "incident",
        "ipv4-addr",
        "domain-name",
        "url",
        "user-agent",
        "note",
        "relationship:related-to",
    },
    calls=["/datadog/api/v2/security_monitoring/signals"],
    description="paged security signals become incidents with their observables and a context note",
)
