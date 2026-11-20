from staticfire.connector_vendors import ConnectorSpec

_TYPES = {"indicator", "malware", "vulnerability", "identity", "relationship:indicates", "report"}

SPECS = [
    ConnectorSpec(
        recipe="taxii2",
        connector="external-import/taxii2",
        env=lambda fake: {
            "TAXII2_DISCOVERY_URL": "https://taxii.staticfire.test/taxii21/",
            "TAXII2_USERNAME": "staticfire",
            "TAXII2_PASSWORD": "staticfire-fake-key",
            "TAXII2_COLLECTIONS": "root.indicators",
            "TAXII2_ENABLE_URL_QUERY_LIMIT": "true",
            "TAXII2_URL_QUERY_LIMIT": "4",
        },
        expected_types=_TYPES | {"ipv4-addr", "domain-name"},
        min_elements=10,
        calls=["/taxii/taxii21/", "/taxii/root/collections/"],
        description="a TAXII 2.1 collection read page by page (limit and next cursor): "
        "indicators, observables, malware, vulnerability, report",
    ),
    ConnectorSpec(
        recipe="taxii2-v20",
        connector="external-import/taxii2",
        env=lambda fake: {
            "TAXII2_DISCOVERY_URL": "https://taxii.staticfire.test/taxii20/",
            "TAXII2_V21": "false",
            "TAXII2_USERNAME": "staticfire",
            "TAXII2_PASSWORD": "staticfire-fake-key",
            "TAXII2_COLLECTIONS": "root20.indicators",
        },
        expected_types=_TYPES,
        min_elements=8,
        calls=["/taxii/taxii20/", "/taxii/root20/collections/"],
        description="a TAXII 2.0 collection read through added_after and the manifest",
    ),
]
