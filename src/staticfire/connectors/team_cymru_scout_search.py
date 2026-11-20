import uuid

from staticfire.connector_vendors import ConnectorSpec


def _indicator(cti) -> str:
    return cti.create_indicator(
        f"staticfire scout {uuid.uuid4().hex[:8]}",
        f"ip = 185.{uuid.uuid4().int % 200 + 10}.{uuid.uuid4().int % 250}.45",
        "Text",
        pattern_type="pure-signal-scout",
    )["id"]


SPEC = ConnectorSpec(
    recipe="team-cymru-scout-search",
    connector="internal-enrichment/team-cymru-scout-search",
    env=lambda fake: {
        "PURE_SIGNAL_SCOUT_API_TOKEN": "staticfire-fake-key",
        "PURE_SIGNAL_SCOUT_API_URL": "https://taxii.cymru.com/api/scout",
    },
    enrich=_indicator,
    expected_types={
        "ipv4-addr",
        "autonomous-system",
        "location",
        "identity",
        "relationship:related-to",
    },
    calls=["/team-cymru/api/scout/search"],
    description="an indicator holding a Scout query (pure-signal-scout pattern type) is "
    "searched and linked to the objects of the answer",
)
