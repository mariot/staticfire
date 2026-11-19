from staticfire.connector_vendors import ConnectorSpec

BASE = "/cyfirma/api/ex/v3/da/stix/2.1"


def _env(fake) -> dict[str, str]:
    return {"CYFIRMA_API_KEY": "staticfire-fake-key"}


SPEC = ConnectorSpec(
    recipe="cyfirma",
    connector="external-import/cyfirma",
    env=_env,
    expected_types={
        "indicator",
        "malware",
        "threat-actor",
        "vulnerability",
        "relationship:indicates",
        "relationship:uses",
    },
    calls=[
        f"{BASE}/indicators/tailored",
        f"{BASE}/threat-actors/search",
        f"{BASE}/vulnerabilities/tailored",
    ],
    description="tailored indicators, the threat actors they name and tailored "
    "vulnerabilities (STIX 2.1 pages) are imported",
)
