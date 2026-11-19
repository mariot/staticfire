import uuid

from staticfire.connector_vendors import ConnectorSpec


def _env(fake) -> dict[str, str]:
    return {
        "ELASTIC_SECURITY_URL": "https://elastic-security-es.staticfire.test",
        "ELASTIC_SECURITY_KIBANA_URL": "https://elastic-security-kb.staticfire.test",
        "ELASTIC_SECURITY_API_KEY": "staticfire-fake-key",
    }


def _kql_indicator(cti) -> list[str]:
    """An indicator whose pattern is a KQL query: it becomes a Kibana detection rule."""
    token = f"sf-{uuid.uuid4().hex[:8]}"
    cti.create_indicator(
        f"staticfire {token}",
        f'destination.domain : "{token}.example.com"',
        "Domain-Name",
        pattern_type="kql",
    )
    return [token]


SPECS = [
    ConnectorSpec(
        recipe="elastic-security-intel",
        connector="stream/elastic-security-intel",
        env=_env,
        calls=["/elastic-security/logs-ti_custom_opencti.indicator/_doc"],
        description="indicators and observables created in OpenCTI are written as threat "
        "intelligence documents to the Elastic data stream",
    ),
    ConnectorSpec(
        recipe="elastic-security-intel-kql",
        connector="stream/elastic-security-intel",
        env=_env,
        stream=_kql_indicator,
        calls=[
            "/elastic-security/api/detection_engine/rules",
            "/elastic-security/logs-ti_custom_opencti.indicator/_doc",
        ],
        description="an indicator with a KQL pattern becomes a Kibana detection rule and a "
        "threat intelligence document",
    ),
]
