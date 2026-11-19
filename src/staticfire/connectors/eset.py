from datetime import UTC, datetime, timedelta

from staticfire.connector_vendors import ConnectorSpec


def env(fake) -> dict[str, str]:
    # The connector polls hour by hour from its start date: start a few hours back. The APT
    # report import (urllib3 on a hardcoded host, ignoring proxies) cannot be served.
    start = datetime.now(UTC) - timedelta(hours=3)
    return {
        "ESET_API_URL": "eti.eset.com",
        "ESET_USERNAME": "staticfire",
        "ESET_PASSWORD": "staticfire-fake-key",
        "ESET_COLLECTIONS": "ei.misp,ei.cc,ei.urls",
        "ESET_IMPORT_APT_REPORTS": "false",
        "ESET_IMPORT_START_DATE": start.strftime("%Y-%m-%dT%H:%M:%S+00:00"),
        "ESET_CREATE_OBSERVABLES": "true",
        "ESET_INTERVAL": "60",
    }


SPEC = ConnectorSpec(
    recipe="eset",
    connector="external-import/eset",
    env=env,
    expected_types={"indicator", "malware", "relationship:indicates"},
    calls=["/eset/taxiiservice/discovery", "/eset/taxiiservice/poll"],
    description="three TAXII 1.1 collections (cabby) become indicators, malware and indicates "
    "links; the APT report import is off (its client ignores proxies)",
)
