from staticfire.connector_vendors import ConnectorSpec

SPEC = ConnectorSpec(
    recipe="splunk",
    connector="stream/splunk",
    env=lambda fake: {
        "SPLUNK_URL": "https://splunk.staticfire.test:8089",
        "SPLUNK_TOKEN": "staticfire-fake-token",
        "SPLUNK_OWNER": "nobody",
        "SPLUNK_APP": "search",
        "SPLUNK_KV_STORE_NAME": "opencti",
        # the compose file's value keeps its quotes
        "SPLUNK_IGNORE_TYPES": "identity,marking-definition,label",
        "CONNECTOR_CONSUMER_COUNT": "2",
    },
    calls=["/splunk-kvstore/servicesNS/nobody/search/storage/collections/"],
    description="stream events are written to the KV store collection (an indicator with its "
    "Splunk query and mapped values, an observable)",
)
