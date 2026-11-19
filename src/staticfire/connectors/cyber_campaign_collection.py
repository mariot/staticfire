from datetime import UTC, datetime

from staticfire.connector_vendors import ConnectorSpec


def _env(fake) -> dict[str, str]:
    return {"CYBER_MONITOR_FROM_YEAR": str(datetime.now(UTC).year - 1)}


SPEC = ConnectorSpec(
    recipe="cyber-campaign-collection",
    connector="external-import/cyber-campaign-collection",
    env=_env,
    expected_types={"report"},
    calls=[
        "/github/repos/CyberMonitor/APT_CyberCriminal_Campagin_Collections/contents",
        "/github/CyberMonitor/APT_CyberCriminal_Campagin_Collections/",
    ],
    description="lists the report folders of the campaign collection (GitHub API), "
    "downloads their files and imports one report per folder",
)
