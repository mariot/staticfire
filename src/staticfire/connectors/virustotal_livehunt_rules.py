import uuid

from staticfire.connector_vendors import ConnectorSpec

PREFIX = "staticfire_livehunt"
# The connector reads the detection flag of every event it receives: it follows its own stream,
# limited to the YARA indicators this test creates.
FILTERS = {
    "mode": "and",
    "filters": [
        {"key": ["entity_type"], "values": ["Indicator"], "operator": "eq", "mode": "or"},
        {"key": ["pattern_type"], "values": ["yara"], "operator": "eq", "mode": "or"},
        {"key": ["pattern"], "values": [PREFIX], "operator": "contains", "mode": "or"},
    ],
    "filterGroups": [],
}


def _yara_indicator(cti) -> list[str]:
    """A YARA indicator with its detection flag on, whose rule name is the marker."""
    name = f"{PREFIX}_{uuid.uuid4().hex[:8]}"
    cti.graphql(
        """mutation ($input: IndicatorAddInput!) { indicatorAdd(input: $input) { id } }""",
        {
            "input": {
                "name": name,
                "pattern": f'rule {name} {{ strings: $a = "staticfire" condition: $a }}',
                "pattern_type": "yara",
                "x_opencti_main_observable_type": "StixFile",
                "x_opencti_detection": True,
            }
        },
    )
    return [name]


SPEC = ConnectorSpec(
    recipe="virustotal-livehunt-rules",
    connector="stream/virustotal-livehunt-rules",
    env=lambda fake: {
        "VIRUSTOTAL_LIVEHUNT_TOKEN": "staticfire-fake-key",
        "VIRUSTOTAL_LIVEHUNT_SHARED_OWNERS": '["staticfire-owner"]',
    },
    stream_filters=FILTERS,
    stream=_yara_indicator,
    calls=["/virustotal/api/v3/intelligence/hunting_rulesets"],
    description="a YARA indicator flagged for detection becomes a VirusTotal Livehunt "
    "ruleset shared with the configured owners (own stream of the test's rules)",
)
