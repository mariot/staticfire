import base64
import json

from staticfire.connector_vendors import ConnectorSpec


def _jwt(login: str) -> str:
    """mwdblib reads the account name from the payload of its API token."""

    def part(data: dict) -> str:
        return base64.b64encode(json.dumps(data).encode()).decode().rstrip("=")

    return f"{part({'alg': 'HS512', 'typ': 'JWT'})}.{part({'login': login})}.signature"


SPEC = ConnectorSpec(
    recipe="mwdb",
    connector="external-import/mwdb",
    env=lambda fake: {
        "MWDB_URL": "https://mwdb.cert.pl/api/",
        "MWDB_TOKEN": _jwt("staticfire"),
        "MWDB_ORG_NAME": "MWDB",
        "MWDB_ORG_DESCRIPTION": "Malware database of CERT Polska",
        "MWDB_START_DATE": "2026-11-01T00:00:00.000Z",
    },
    expected_types={
        "malware",
        "indicator",
        "file",
        "ipv4-addr",
        "url",
        "relationship:indicates",
        "relationship:based-on",
        "relationship:related-to",
    },
    calls=["/mwdb/api/file", "/mwdb/api/config/"],
    description="recent MWDB files with their tags and static configs (C2 IPs and URLs)",
)
