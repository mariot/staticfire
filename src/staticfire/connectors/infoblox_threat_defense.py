import time
import urllib.request
import uuid
from datetime import UTC, datetime
from email.utils import parsedate_to_datetime

from staticfire import config
from staticfire.connector_vendors import ConnectorSpec

DOMAIN = "infoblox.staticfire.example.com"
# The connector sleeps 5 s per event: it follows its own stream, limited to the domain
# indicators the test creates, instead of the changes of the whole platform
FILTERS = {
    "mode": "and",
    "filters": [
        {"key": ["entity_type"], "values": ["Indicator"], "operator": "eq", "mode": "or"},
        {"key": ["pattern"], "values": [DOMAIN], "operator": "contains", "mode": "or"},
    ],
    "filterGroups": [],
}


def _domain_indicator(cti) -> list[str]:
    domain = f"sf-{uuid.uuid4().hex[:8]}.{DOMAIN}"
    cti.create_indicator(f"staticfire {domain}", f"[domain-name:value = '{domain}']", "Domain-Name")
    return [domain]


def _platform_now() -> float:
    """The platform's clock, which may differ from this host's (a paused VM)."""
    try:
        for name in config.list_profiles():
            url = config.load_profile(name).opencti_url
            if url:
                request = urllib.request.Request(f"{url}/health", method="HEAD")
                with urllib.request.urlopen(request, timeout=10) as response:
                    return parsedate_to_datetime(response.headers["Date"]).timestamp()
    except Exception:
        pass
    return time.time()


def _env(fake) -> dict[str, str]:
    # The stream is read from the platform's present, whatever its clock says compared to this
    # host's (the connector asks to recover events up to its own now, which the platform may
    # not have reached)
    start = _platform_now() - 10
    return {
        "INFOBLOX_API_KEY": "staticfire-fake-key",
        "INFOBLOX_CUSTOM_LIST_ID": "123456",
        "INFOBLOX_URL": "https://csp.infoblox.com",
        "CONNECTOR_LIVE_STREAM_START_TIMESTAMP": str(int(start * 1000)),
        "CONNECTOR_LIVE_STREAM_RECOVER_ISO_DATE": datetime.fromtimestamp(start, UTC).strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        ),
    }


SPEC = ConnectorSpec(
    recipe="infoblox-threat-defense",
    connector="stream/infoblox-threat-defense",
    env=_env,
    stream_filters=FILTERS,
    stream=_domain_indicator,
    calls=["/infoblox/api/atcfw/v1/named_lists/123456"],
    description="a new domain indicator is added to the Threat Defense custom list (GET then PUT)",
)
