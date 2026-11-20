from staticfire.connector_vendors import ConnectorSpec

_ENV = {
    "THREATLANDSCAPE_API_BASE_URL": "https://api.threatlandscape.io/rest/v1",
    "THREATLANDSCAPE_API_KEY": "staticfire-fake-key",
    "THREATLANDSCAPE_PAGE_SIZE": "3",
}

SPECS = [
    ConnectorSpec(
        recipe="threatlandscape",
        connector="external-import/threatlandscape",
        env=lambda fake: {**_ENV, "THREATLANDSCAPE_FEED": "intelligence"},
        expected_types={
            "report",
            "threat-actor",
            "intrusion-set",
            "campaign",
            "malware",
            "attack-pattern",
            "vulnerability",
            "location",
            "indicator",
            "ipv4-addr",
            "relationship:uses",
            "relationship:targets",
        },
        min_elements=10,
        calls=["/threatlandscape/rest/v1/stix_bundles"],
        description="the intelligence feed read three bundles per page through the seq_id cursor",
    ),
    ConnectorSpec(
        recipe="threatlandscape-ioc",
        connector="external-import/threatlandscape",
        env=lambda fake: {**_ENV, "THREATLANDSCAPE_FEED": "ioc"},
        expected_types={"indicator", "ipv4-addr", "malware", "relationship:indicates"},
        calls=["/threatlandscape/rest/v1/actionable_iocs"],
        description="the actionable IOC feed (indicators on addresses and their malware)",
    ),
]
