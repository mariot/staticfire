from staticfire.connector_vendors import ConnectorSpec


def _env(fake) -> dict[str, str]:
    return {"DARK_WEB_INFORMER_API_KEY": "staticfire-fake-key"}


SPEC = ConnectorSpec(
    recipe="dark-web-informer",
    connector="external-import/dark-web-informer",
    env=_env,
    expected_types={
        "indicator",
        "ipv4-addr",
        "malware",
        "intrusion-set",
        "report",
        "relationship:indicates",
        "relationship:targets",
    },
    calls=[
        "/dark-web-informer/api/stix/export_feed.json",
        "/dark-web-informer/api/stix/export_ransomware.json",
        "/dark-web-informer/api/stix/export_iocs.json",
    ],
    description="the feed, ransomware and IOC STIX bundles are forwarded with the "
    "connector's author and TLP marking",
)
