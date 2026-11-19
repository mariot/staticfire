from staticfire.connector_vendors import ConnectorSpec

SPEC = ConnectorSpec(
    recipe="arcsight",
    connector="stream/arcsight",
    env=lambda fake: {
        "ARCSIGHT_API_BASE_URL": "https://arcsight.staticfire.test:8443",
        "ARCSIGHT_USERNAME": "staticfire",
        "ARCSIGHT_PASSWORD": "staticfire-fake-password",
        "ARCSIGHT_ACTIVE_LIST_ID": "STATICFIRE-ACTIVE-LIST",
    },
    calls=["/arcsight/www/manager-service/rest/ActiveListService/addEntries"],
    description="a new indicator is added to the ESM active list",
)
