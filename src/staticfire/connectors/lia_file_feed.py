from staticfire.connector_vendors import ConnectorSpec

SPEC = ConnectorSpec(
    recipe="lia-file-feed",
    connector="external-import/lia-file-feed",
    env=lambda fake: {
        "LIA_API_KEY": "staticfire-fake-key",
        "LIA_BASE_API_URL": "https://loaderinsight.agency/api/?ep=filefeed",
    },
    expected_types={"indicator", "malware", "file", "url", "relationship:downloads"},
    calls=["/lia/api"],
    description="loader payloads become file and URL indicators and observables, linked to "
    "the loader and detected malware families",
)
