import os
from pathlib import Path

from staticfire.connector_vendors import ConnectorSpec

# entrypoint.sh runs ``python3 -m src`` from /opt, where src/ is a package: the tool runs it from
# src/ itself, so the connector's root goes on the module path
ROOT = Path(os.environ.get("STATICFIRE_CONNECTORS_DIR", Path.home() / "GitHub" / "connectors"))

SPEC = ConnectorSpec(
    recipe="servicenow",
    connector="external-import/servicenow",
    env=lambda fake: {
        "PYTHONPATH": str(ROOT / "external-import" / "servicenow"),
        "SERVICENOW_INSTANCE_NAME": "staticfire",
        "SERVICENOW_API_KEY": "staticfire-fake-key",
        "SERVICENOW_IMPORT_START_DATE": "P3D",
    },
    expected_types={
        "case-incident",
        "task",
        "attack-pattern",
        "intrusion-set",
        "malware",
        "tool",
        "email-addr",
        "hostname",
        "autonomous-system",
        "file",
        "domain-name",
        "ipv4-addr",
        "url",
    },
    calls=[
        "/servicenow/api/now/v2/table/sn_si_incident",
        "/servicenow/api/now/v2/table/sn_si_task",
        "/servicenow/api/now/v2/table/sn_ti_m2m_task_observable",
    ],
    description="security incidents become case incidents with their tasks, MITRE objects "
    "and observables of each main kind (promoted to indicators by the platform)",
)
